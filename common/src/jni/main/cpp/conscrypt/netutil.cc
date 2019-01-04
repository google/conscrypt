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

#include <conscrypt/netutil.h>
#include <conscrypt/trace.h>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#else  // !_WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef CONSCRYPT_UNBUNDLED
#include <dlfcn.h>
#endif  // CONSCRYPT_UNBUNDLED
#endif  // !_WIN32

namespace conscrypt {
namespace netutil {

/**
 * Copied from libnativehelper NetworkUtilites.cpp
 */
bool setBlocking(int fd, bool blocking) {
#ifdef _WIN32
    unsigned long flag = blocking ? 0UL : 1UL;  // NOLINT(runtime/int)
    int res = ioctlsocket(fd, FIONBIO, &flag);
    if (res != NO_ERROR) {
        JNI_TRACE("ioctlsocket %d failed with error: %d", fd, WSAGetLastError());
    }
    return res == NO_ERROR;
#else
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return false;
    }

    if (!blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    return fcntl(fd, F_SETFL, flags) != -1;
#endif
}

}  // namespace netutil
}  // namespace conscrypt
