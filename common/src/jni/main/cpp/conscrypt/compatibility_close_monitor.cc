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

#include <dlfcn.h>

namespace conscrypt {

CompatibilityCloseMonitor::acm_create_func CompatibilityCloseMonitor::asyncCloseMonitorCreate =
        nullptr;
CompatibilityCloseMonitor::acm_destroy_func CompatibilityCloseMonitor::asyncCloseMonitorDestroy =
        nullptr;

void CompatibilityCloseMonitor::init() {
    void *lib = dlopen("libjavacore.so", RTLD_NOW);
    if (lib != nullptr) {
        asyncCloseMonitorCreate = (acm_create_func)dlsym(lib, "async_close_monitor_create");
        asyncCloseMonitorDestroy = (acm_destroy_func)dlsym(lib, "async_close_monitor_destroy");
    }
}

}  // namespace conscrypt
