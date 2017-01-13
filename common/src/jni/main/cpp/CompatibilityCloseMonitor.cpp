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

#include "CompatibilityCloseMonitor.h"

#if defined(CONSCRYPT_UNBUNDLED) && !defined(CONSCRYPT_OPENJDK)

#include <dlfcn.h>

using namespace conscrypt;

CompatibilityCloseMonitor::acm_ctor_func CompatibilityCloseMonitor::asyncCloseMonitorConstructor =
        nullptr;
CompatibilityCloseMonitor::acm_dtor_func CompatibilityCloseMonitor::asyncCloseMonitorDestructor =
        nullptr;

void CompatibilityCloseMonitor::init() {
    void *lib = dlopen("libjavacore.so", RTLD_NOW);
    if (lib != nullptr) {
        asyncCloseMonitorConstructor =
                (acm_ctor_func)dlsym(lib, "_ZN24AsynchronousCloseMonitorC1Ei");
        asyncCloseMonitorDestructor =
                (acm_dtor_func)dlsym(lib, "_ZN24AsynchronousCloseMonitorD1Ev");
    }
}

#endif  // CONSCRYPT_UNBUNDLED && !CONSCRYPT_OPENJDK
