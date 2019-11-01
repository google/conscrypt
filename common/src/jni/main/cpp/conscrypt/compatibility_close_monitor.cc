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

#include <conscrypt/compatibility_close_monitor.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

namespace conscrypt {

CompatibilityCloseMonitor::acm_create_func CompatibilityCloseMonitor::asyncCloseMonitorCreate =
        nullptr;
CompatibilityCloseMonitor::acm_destroy_func CompatibilityCloseMonitor::asyncCloseMonitorDestroy =
        nullptr;

#ifdef CONSCRYPT_UNBUNDLED
CompatibilityCloseMonitor::acm_ctor_func CompatibilityCloseMonitor::asyncCloseMonitorConstructor =
        nullptr;
CompatibilityCloseMonitor::acm_dtor_func CompatibilityCloseMonitor::asyncCloseMonitorDestructor =
        nullptr;
#endif  // CONSCRYPT_UNBUNDLED

void CompatibilityCloseMonitor::init() {
#ifndef _WIN32
    void *lib = dlopen("libandroidio.so", RTLD_NOW);
    if (lib != nullptr) {
        asyncCloseMonitorCreate = (acm_create_func) dlsym(lib, "async_close_monitor_create");
        asyncCloseMonitorDestroy = (acm_destroy_func) dlsym(lib, "async_close_monitor_destroy");
        return;
    }
#ifdef CONSCRYPT_UNBUNDLED
    // Only attempt to initialise the legacy C++ API if the C API symbols were not found.
    lib = dlopen("libjavacore.so", RTLD_NOW);
    if (lib != nullptr) {
        if (asyncCloseMonitorCreate == nullptr) {
            asyncCloseMonitorConstructor =
                    (acm_ctor_func)dlsym(lib, "_ZN24AsynchronousCloseMonitorC1Ei");
            asyncCloseMonitorDestructor =
                    (acm_dtor_func)dlsym(lib, "_ZN24AsynchronousCloseMonitorD1Ev");
        }
    }
#endif  // CONSCRYPT_UNBUNDLED
#endif  // _WIN32
}
}  // namespace conscrypt
