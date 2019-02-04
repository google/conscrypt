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
 * On non-Android platforms, this class becomes a no-op as the function pointers
 * to create and destroy AsynchronousCloseMonitor instances will be null.
 */
class CompatibilityCloseMonitor {
 public:
     explicit CompatibilityCloseMonitor(int fd) : monitor(nullptr) {
         if (asyncCloseMonitorCreate != nullptr) {
             monitor = asyncCloseMonitorCreate(fd);
         }
    }

    ~CompatibilityCloseMonitor() {
        if (asyncCloseMonitorDestroy != nullptr && monitor != nullptr) {
            asyncCloseMonitorDestroy(monitor);
        }
    }

    static void init();

 private:
     typedef void* (*acm_create_func)(int);
     typedef void (*acm_destroy_func)(void*);

     // Pointer to async_close_monitor_create(). This will be null on platforms other than Android.
     static acm_create_func asyncCloseMonitorCreate;

     // Pointer to async_close_monitor_destroy(). This will be null on platforms other than Android.
     static acm_destroy_func asyncCloseMonitorDestroy;

     // Pointer to active monitor.
     void* monitor;
};

}  // namespace conscrypt

#endif  // CONSCRYPT_COMPATIBILITY_CLOSE_MONITOR_H_
