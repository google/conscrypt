/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef CONSCRYPT_LOGGING_H_
#define CONSCRYPT_LOGGING_H_

#include <conscrypt/macros.h>

#define LOG_TAG "NativeCrypto"

#ifndef CONSCRYPT_UNBUNDLED

#include <log/log.h>

#define CONSCRYPT_LOG(priority, tag, ...) ALOG(priority, tag, __VA_ARGS__)
#define CONSCRYPT_LOG_ERROR(...) ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define CONSCRYPT_LOG_INFO(...) ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)
#if LOG_NDEBUG
#define CONSCRYPT_LOG_VERBOSE(...) ((void)0)
#else
#define CONSCRYPT_LOG_VERBOSE(...) ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif  // LOG_DEBUG

#elif defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)  // !CONSCRYPT_UNBUNDLED

#include <android/log.h>
#ifndef ALOG
#define ALOG(priority, tag, ...) __android_log_print(ANDROID_##priority, tag, __VA_ARGS__)
#endif

#define CONSCRYPT_LOG(priority, tag, ...) ALOG(priority, tag, __VA_ARGS__)
#define CONSCRYPT_LOG_ERROR(...) ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define CONSCRYPT_LOG_INFO(...) ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)
#if LOG_NDEBUG
#define CONSCRYPT_LOG_VERBOSE(...) ((void)0)
#else
#define CONSCRYPT_LOG_VERBOSE(...) ALOG(LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif

#else  // !ANDROID

// LOG_NDEBUG is an Android property that turns off verbose logging
#ifndef LOG_NDEBUG
#define LOG_NDEBUG 1
#endif

#include <stdio.h>

#define CONSCRYPT_LOG(priority, tag, ...) CONSCRYPT_##priority(__VA_ARGS__)

#define CONSCRYPT_LOG_ERROR(...) {   \
    fprintf(stderr, __VA_ARGS__);    \
    fprintf(stderr, "\n");           \
}
#define CONSCRYPT_LOG_INFO(...) {    \
    fprintf(stderr, __VA_ARGS__);    \
    fprintf(stderr, "\n");           \
}
#if LOG_NDEBUG
#define CONSCRYPT_LOG_VERBOSE(...) ((void)0)
#else
#define CONSCRYPT_LOG_VERBOSE(...) { \
    fprintf(stderr, __VA_ARGS__);    \
    fprintf(stderr, "\n");           \
}
#endif  // LOG_NDEBUG

#endif  // !ANDROID

#endif  // CONSCRYPT_LOGGING_H_
