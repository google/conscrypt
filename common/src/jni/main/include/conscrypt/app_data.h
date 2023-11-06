/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONSCRYPT_APP_DATA_H_
#define CONSCRYPT_APP_DATA_H_

#include <conscrypt/NetFd.h>
#include <conscrypt/compat.h>
#include <conscrypt/jniutil.h>
#include <conscrypt/netutil.h>
#include <conscrypt/trace.h>

#include <jni.h>
#include <atomic>
#include <memory>
#include <mutex>  // NOLINT(build/c++11)

#ifdef _WIN32
// Needed for inet_ntop
#define _WIN32_WINNT _WIN32_WINNT_WIN8
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <winsock2.h>
#else  // !_WIN32
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#endif  // !_WIN32

namespace conscrypt {

/**
 * Our additional application data needed for getting synchronization right.
 * This maybe warrants a bit of lengthy prose:
 *
 * (1) We use a flag to reflect whether we consider the SSL connection alive.
 * Any read or write attempt loops will be cancelled once this flag becomes 0.
 *
 * (2) We use an int to count the number of threads that are blocked by the
 * underlying socket. This may be at most two (one reader and one writer), since
 * the Java layer ensures that no more threads will enter the native code at the
 * same time.
 *
 * (3) The pipe is used primarily as a means of cancelling a blocking select()
 * when we want to close the connection (aka "emergency button"). It is also
 * necessary for dealing with a possible race condition situation: There might
 * be cases where both threads see an SSL_ERROR_WANT_READ or
 * SSL_ERROR_WANT_WRITE. Both will enter a select() with the proper argument.
 * If one leaves the select() successfully before the other enters it, the
 * "success" event is already consumed and the second thread will be blocked,
 * possibly forever (depending on network conditions).
 *
 * The idea for solving the problem looks like this: Whenever a thread is
 * successful in moving around data on the network, and it knows there is
 * another thread stuck in a select(), it will write a byte to the pipe, waking
 * up the other thread. A thread that returned from select(), on the other hand,
 * knows whether it's been woken up by the pipe. If so, it will consume the
 * byte, and the original state of affairs has been restored.
 *
 * The pipe may seem like a bit of overhead, but it fits in nicely with the
 * other file descriptors of the select(), so there's only one condition to wait
 * for.
 *
 * (4) Finally, a mutex is needed to make sure that at most one thread is in
 * either SSL_read() or SSL_write() at any given time. This is an OpenSSL
 * requirement. We use the same mutex to guard the field for counting the
 * waiting threads.
 *
 * During handshaking, additional fields are used to up-call into
 * Java to perform certificate verification and handshake
 * completion. These are also used in any renegotiation.
 *
 * (5) the JNIEnv so we can invoke the Java callback
 *
 * (6) a NativeCrypto.SSLHandshakeCallbacks instance for callbacks from native to Java
 *
 * (7) a java.io.FileDescriptor wrapper to check for socket close
 *
 * We store the ALPN protocols list so we can either send it (from the server) or
 * select a protocol (on the client). We eagerly acquire a pointer to the array
 * data so the callback doesn't need to acquire resources that it cannot
 * release.
 *
 * Because renegotiation can be requested by the peer at any time,
 * care should be taken to maintain an appropriate JNIEnv on any
 * downcall to openssl since it could result in an upcall to Java. The
 * current code does try to cover these cases by conditionally setting
 * the JNIEnv on calls that can read and write to the SSL such as
 * SSL_do_handshake, SSL_read, SSL_write, and SSL_shutdown.
 */
class AppData {
 public:
    std::atomic<bool> aliveAndKicking;
    int waitingThreads;
#ifdef _WIN32
    HANDLE interruptEvent;
#else
    int fdsEmergency[2];
#endif
    std::mutex mutex;
    JNIEnv* env;
    jobject sslHandshakeCallbacks;
    char* applicationProtocolsData;
    size_t applicationProtocolsLength;
    bool hasApplicationProtocolSelector;

    /**
     * Creates the application data context for the SSL*.
     */
    static AppData* create() {
        std::unique_ptr<AppData> appData(new AppData());
#ifdef _WIN32
        HANDLE interruptEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (interruptEvent == nullptr) {
            JNI_TRACE("AppData::create WSACreateEvent failed: %d", WSAGetLastError());
            return nullptr;
        }
        appData.get()->interruptEvent = interruptEvent;
#else
        if (pipe(appData.get()->fdsEmergency) == -1) {
            CONSCRYPT_LOG_ERROR("AppData::create pipe(2) failed: %s", strerror(errno));
            return nullptr;
        }
        if (!netutil::setBlocking(appData.get()->fdsEmergency[0], false)) {
            CONSCRYPT_LOG_ERROR("AppData::create fcntl(2) failed: %s", strerror(errno));
            return nullptr;
        }
#endif
        return appData.release();
    }

    ~AppData() {
        aliveAndKicking = false;
#ifdef _WIN32
        if (interruptEvent != nullptr) {
            CloseHandle(interruptEvent);
        }
#else
        if (fdsEmergency[0] != -1) {
            close(fdsEmergency[0]);
        }
        if (fdsEmergency[1] != -1) {
            close(fdsEmergency[1]);
        }
#endif
        clearApplicationProtocols();
        clearCallbackState();
    }

    /**
     * Only called in server mode. Sets the protocols for ALPN negotiation.
     *
     * @param env The JNIEnv
     * @param alpnProtocols ALPN protocols so that they may be advertised (by the
     *                     server) or selected (by the client). Passing
     *                     non-null enables ALPN. This array is copied so that no
     *                     global reference to the Java byte array is maintained.
     */
    bool setApplicationProtocols(JNIEnv* e, jbyteArray applicationProtocolsJava) {
        clearApplicationProtocols();
        if (applicationProtocolsJava != nullptr) {
            jbyte* applicationProtocols =
                e->GetByteArrayElements(applicationProtocolsJava, nullptr);
            if (applicationProtocols == nullptr) {
                clearCallbackState();
                JNI_TRACE("appData=%p setApplicationCallbackState => applicationProtocols == null",
                          this);
                return false;
            }
            applicationProtocolsLength =
                static_cast<size_t>(e->GetArrayLength(applicationProtocolsJava));
            applicationProtocolsData = new char[applicationProtocolsLength];
            memcpy(applicationProtocolsData, applicationProtocols, applicationProtocolsLength);
            e->ReleaseByteArrayElements(applicationProtocolsJava, applicationProtocols, JNI_ABORT);
        }
        return true;
    }

    /**
     * Used to set the SSL-to-Java callback state before each SSL_*
     * call that may result in a callback. It should be cleared after
     * the operation returns with clearCallbackState.
     *
     * @param env The JNIEnv
     * @param shc The SSLHandshakeCallbacks
     * @param fd The FileDescriptor
     */
    bool setCallbackState(JNIEnv* e, jobject shc, jobject fd) {
        std::unique_ptr<NetFd> netFd;
        if (fd != nullptr) {
            netFd.reset(new NetFd(e, fd));
            if (netFd->isClosed()) {
                JNI_TRACE("appData=%p setCallbackState => netFd->isClosed() == true", this);
                return false;
            }
        }
        env = e;
        sslHandshakeCallbacks = shc;
        return true;
    }

    void clearCallbackState() {
        sslHandshakeCallbacks = nullptr;
        env = nullptr;
    }

 private:
    AppData()
        : aliveAndKicking(true),
          waitingThreads(0),
          env(nullptr),
          sslHandshakeCallbacks(nullptr),
          applicationProtocolsData(nullptr),
          applicationProtocolsLength(static_cast<size_t>(-1)),
          hasApplicationProtocolSelector(false) {
#ifdef _WIN32
        interruptEvent = nullptr;
#else
        fdsEmergency[0] = -1;
        fdsEmergency[1] = -1;
#endif
    }

    void clearApplicationProtocols() {
        if (applicationProtocolsData != nullptr) {
            delete[] applicationProtocolsData;
            applicationProtocolsData = nullptr;
            applicationProtocolsLength = static_cast<size_t>(-1);
        }
    }
};

}  // namespace conscrypt

#endif  // CONSCRYPT_APP_DATA_H_
