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

#ifndef CONSCRYPT_COMPATIBILITYCLOSEMONITOR_H_
#define CONSCRYPT_COMPATIBILITYCLOSEMONITOR_H_

#include "macros.h"

#ifndef CONSCRYPT_UNBUNDLED

/* If we're compiled unbundled from Android system image, we use the
 * CompatibilityCloseMonitor
 */
#include "AsynchronousCloseMonitor.h"

namespace conscrypt {

/**
 * When bundled with Android, this just wraps around AsynchronousCloseMonitor.
 */
class CompatibilityCloseMonitor {
private:
    AsynchronousCloseMonitor monitor;

public:
    CompatibilityCloseMonitor(int fd) : monitor(fd) {}

    ~CompatibilityCloseMonitor() {}

    static void init() {}
};

}  // namespace conscrypt

#elif !defined(CONSCRYPT_OPENJDK)  // && CONSCRYPT_UNBUNDLED

namespace conscrypt {

/*
 * This is a big hack; don't learn from this. Basically what happened is we do
 * not have an API way to insert ourselves into the AsynchronousCloseMonitor
 * that's compiled into the native libraries for libcore when we're unbundled.
 * So we try to look up the symbol from the main library to find it.
 */
class CompatibilityCloseMonitor {
public:
    CompatibilityCloseMonitor(int fd) {
        if (asyncCloseMonitorConstructor != nullptr) {
            asyncCloseMonitorConstructor(objBuffer, fd);
        }
    }

    ~CompatibilityCloseMonitor() {
        if (asyncCloseMonitorDestructor != nullptr) {
            asyncCloseMonitorDestructor(objBuffer);
        }
    }

    static void init();

private:
    typedef void (*acm_ctor_func)(void*, int);
    typedef void (*acm_dtor_func)(void*);

    static acm_ctor_func asyncCloseMonitorConstructor;
    static acm_dtor_func asyncCloseMonitorDestructor;

    char objBuffer[256];
#if 0
    static_assert(sizeof(objBuffer) > 2*sizeof(AsynchronousCloseMonitor),
                  "CompatibilityCloseMonitor must be larger than the actual object");
#endif
};

}  // namespace conscrypt

#else  // CONSCRYPT_UNBUNDLED && CONSCRYPT_OPENJDK

namespace conscrypt {

/**
 * For OpenJDK, do nothing.
 */
class CompatibilityCloseMonitor {
public:
    CompatibilityCloseMonitor(int) {}

    ~CompatibilityCloseMonitor() {}

    static void init() {}
};

}  // namespace conscrypt

#endif  // CONSCRYPT_UNBUNDLED && CONSCRYPT_OPENJDK

#endif  // CONSCRYPT_COMPATIBILITYCLOSEMONITOR_H_
