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

#ifndef CONSCRYPT_LOG_H_
#define CONSCRYPT_LOG_H_

#include <stdio.h>
#include <stdarg.h>

#include <mutex>

namespace conscrypt {

// TODO: Determine how to initialize safely. It would be nice to place this into a hidden namespace, but that prevents
// us from accessing it in the function template.
extern std::mutex g_log_lock;

template <typename... Args>
void loge(const char* format, Args... args) {
    std::lock_guard<std::mutex> guard(g_log_lock);
    fprintf(stderr, format, args...);
    fprintf(stderr, "\n");
    fflush(stderr);
}

}  // namespace conscrypt

#endif  // CONSCRYPT_LOG_H_
