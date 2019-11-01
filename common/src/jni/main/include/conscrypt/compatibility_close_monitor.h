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

#ifndef CONSCRYPT_COMPATIBILITY_CLOSE_MONITOR_H_
#define CONSCRYPT_COMPATIBILITY_CLOSE_MONITOR_H_

#include <conscrypt/macros.h>

namespace conscrypt {

/*
 * Where possible, this class hooks into the Android C API for AsynchronousCloseMonitor,
 * allowing Java thread wakeup semantics during POSIX system calls. It is only used in sslSelect().
 *
 * When unbundled, if the C API methods are not available, this class will fall
 * back to looking for the C++ API methods which existed on Android P and below.
 *
 * On non-Android platforms, this class becomes a no-op as all of the function pointers
 * to create and destroy AsynchronousCloseMonitor instances will be null.
 */
class CompatibilityCloseMonitor {
 public:
     explicit CompatibilityCloseMonitor(int fd) : monitor(nullptr) {
         if (asyncCloseMonitorCreate != nullptr) {
             monitor = asyncCloseMonitorCreate(fd);
         }
#ifdef CONSCRYPT_UNBUNDLED
         else if (asyncCloseMonitorConstructor != nullptr) {  // NOLINT(readability/braces)
             asyncCloseMonitorConstructor(objBuffer, fd);
         }
#endif  // CONSCRYPT_UNBUNDLED
    }

    ~CompatibilityCloseMonitor() {
        if (asyncCloseMonitorDestroy != nullptr) {
            if (monitor != nullptr) {
                asyncCloseMonitorDestroy(monitor);
            }
        }
#ifdef CONSCRYPT_UNBUNDLED
        else if (asyncCloseMonitorDestructor != nullptr) {  // NOLINT(readability/braces)
            asyncCloseMonitorDestructor(objBuffer);
        }
#endif  // CONSCRYPT_UNBUNDLED
    }

    static void init();

 private:
     // C API: Not available on Android P and below. Maintains pointers to the C
     // create and destroy methods, which will be null on non-Android platforms.
     // The handle returned by the create method is stored in monitor.
     typedef void* (*acm_create_func)(int);
     typedef void (*acm_destroy_func)(void*);

     static acm_create_func asyncCloseMonitorCreate;
     static acm_destroy_func asyncCloseMonitorDestroy;
     void* monitor;

#ifdef CONSCRYPT_UNBUNDLED
     // C++ API: Only available on Android P and below. Maintains pointers to
     // the C++ constructor and destructor methods, which will be null on
     // non-Android platforms.  Calls them directly, passing in a pointer to
     // objBuffer, which is large enough to fit an AsynchronousCloseMonitor object on
     // Android versions where this class will be using this API.
     // This is equivalent to placement new and explicit destruction.
     typedef void (*acm_ctor_func)(void*, int);
     typedef void (*acm_dtor_func)(void*);

     static acm_ctor_func asyncCloseMonitorConstructor;
     static acm_dtor_func asyncCloseMonitorDestructor;
     char objBuffer[256];
#endif  // CONSCRYPT_UNBUNDLED
};

}  // namespace conscrypt

#endif  // CONSCRYPT_COMPATIBILITY_CLOSE_MONITOR_H_
