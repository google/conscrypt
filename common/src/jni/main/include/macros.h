/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef CONSCRYPT_SRC_MAIN_NATIVE_MACROS_H_
#define CONSCRYPT_SRC_MAIN_NATIVE_MACROS_H_

#define TO_STRING1(x) #x
#define TO_STRING(x) TO_STRING1(x)
#ifndef JNI_JARJAR_PREFIX
#ifndef CONSCRYPT_NOT_UNBUNDLED
#define CONSCRYPT_UNBUNDLED
#endif
#define JNI_JARJAR_PREFIX
#endif

// The FALLTHROUGH_INTENDED macro can be used to annotate implicit fall-through
// between switch labels:
//  switch (x) {
//    case 40:
//    case 41:
//      if (truth_is_out_there) {
//        ++x;
//        FALLTHROUGH_INTENDED;  // Use instead of/along with annotations in
//                               // comments.
//      } else {
//        return x;
//      }
//    case 42:
//      ...
//
//  As shown in the example above, the FALLTHROUGH_INTENDED macro should be
//  followed by a semicolon. It is designed to mimic control-flow statements
//  like 'break;', so it can be placed in most places where 'break;' can, but
//  only if there are no statements on the execution path between it and the
//  next switch label.
//
//  When compiled with clang in C++11 mode, the FALLTHROUGH_INTENDED macro is
//  expanded to [[clang::fallthrough]] attribute, which is analysed when
//  performing switch labels fall-through diagnostic ('-Wimplicit-fallthrough').
//  See clang documentation on language extensions for details:
//  http://clang.llvm.org/docs/LanguageExtensions.html#clang__fallthrough
//
//  When used with unsupported compilers, the FALLTHROUGH_INTENDED macro has no
//  effect on diagnostics.
//
//  In either case this macro has no effect on runtime behavior and performance
//  of code.
#if defined(__clang__) && __cplusplus >= 201103L && defined(__has_warning)
#if __has_feature(cxx_attributes) && __has_warning("-Wimplicit-fallthrough")
#define FALLTHROUGH_INTENDED [[clang::fallthrough]]  // NOLINT
#endif
#endif

#ifndef FALLTHROUGH_INTENDED
#define FALLTHROUGH_INTENDED \
    do {                     \
    } while (0)
#endif

#if defined _WIN32 || defined __CYGWIN__
#ifdef __GNUC__
#define CONSCRYPT_PUBLIC __attribute__((dllexport))
#else
#define CONSCRYPT_PUBLIC __declspec(dllexport)
#endif
#define CONSCRYPT_LOCAL
#else
#if __GNUC__ >= 4
#define CONSCRYPT_PUBLIC __attribute__((visibility("default")))
#define CONSCRYPT_LOCAL __attribute__((visibility("hidden")))
#else
#define CONSCRYPT_PUBLIC
#define CONSCRYPT_LOCAL
#endif
#endif

#ifdef __GNUC__
#define CONSCRYPT_UNUSED __attribute__((unused))
#define CONSCRYPT_WARN_UNUSED __attribute__((warn_unused_result))
#elif defined(_WIN32)
#define CONSCRYPT_UNUSED __pragma(warning(suppress : 4100))
#define CONSCRYPT_WARN_UNUSED _Check_return_
#else
#define CONSCRYPT_UNUSED
#define CONSCRYPT_WARN_UNUSED
#endif

#ifndef NELEM
#define NELEM(x) ((int)(sizeof(x) / sizeof((x)[0])))
#endif

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument
 * on failure. This means we need to tell our scoped pointers when we've transferred ownership,
 * without triggering a warning by not using the result of release().
 */
#define OWNERSHIP_TRANSFERRED(obj)                                           \
    do {                                                                     \
        decltype((obj).release()) CONSCRYPT_UNUSED _dummy = (obj).release(); \
    } while (0)

/**
 * UNUSED_ARGUMENT can be used to mark an, otherwise unused, argument as "used"
 * for the purposes of -Werror=unused-parameter. This can be needed when an
 * argument's use is based on an #ifdef.
 */
#define UNUSED_ARGUMENT(x) ((void)(x));

/**
 * Check array bounds for arguments when an array and offset are given.
 */
#define ARRAY_OFFSET_INVALID(array, offset) \
    ((offset) < 0 || (offset) > static_cast<ssize_t>((array).size()))

/**
 * Check array bounds for arguments when an array, offset, and length are given.
 */
#define ARRAY_OFFSET_LENGTH_INVALID(array, offset, len)                              \
    ((offset) < 0 || (offset) > static_cast<ssize_t>((array).size()) || (len) < 0 || \
     (len) > static_cast<ssize_t>((array).size()) - (offset))

/**
 * Check array bounds for arguments when an array length, chunk offset, and chunk length are given.
 */
#define ARRAY_CHUNK_INVALID(array_len, chunk_offset, chunk_len)                                   \
    ((chunk_offset) < 0 || (chunk_offset) > static_cast<ssize_t>(array_len) || (chunk_len) < 0 || \
     (chunk_len) > static_cast<ssize_t>(array_len) - (chunk_offset))

// Define logging macros...

#define LOG_TAG "NativeCrypto"

#ifndef CONSCRYPT_UNBUNDLED

#include <log/log.h>

#elif defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)

#include <android/log.h>
#ifndef ALOG
#define ALOG(priority, tag, ...) __android_log_print(ANDROID_##priority, tag, __VA_ARGS__)
#endif
#ifndef ALOGD
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif
#ifndef ALOGE
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

#ifndef __ALOGV
#define __ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif
#ifndef ALOGV
#if LOG_NDEBUG
#define ALOGV(...)                \
    do {                          \
        if (0) {                  \
            __ALOGV(__VA_ARGS__); \
        }                         \
    } while (0)
#else
#define ALOGV(...) __ALOGV(__VA_ARGS__)
#endif
#endif

#else  // !ANDROID

#define LOG_INFO ((void)0)

#define ALOG(...) VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGD(...) VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGE(...) VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGV(...) VA_ARGS_UNUSED(__VA_ARGS__)

#define UNUSED_1(a) ((void)(a))
#define UNUSED_2(a, b) ((void)(a)), UNUSED_1(b)
#define UNUSED_3(a, b, c) ((void)(a)), UNUSED_2(b, c)
#define UNUSED_4(a, b, c, d) ((void)(a)), UNUSED_3(b, c, d)
#define UNUSED_5(a, b, c, d, e) ((void)(a)), UNUSED_4(b, c, d, e)
#define UNUSED_6(a, b, c, d, e, f) ((void)(a)), UNUSED_5(b, c, d, e, f)
#define UNUSED_7(a, b, c, d, e, f, g) ((void)(a)), UNUSED_6(b, c, d, e, f, g)
#define UNUSED_8(a, b, c, d, e, f, g, h) ((void)(a)), UNUSED_7(b, c, d, e, f, g, h)
#define UNUSED_9(a, b, c, d, e, f, g, h, i) ((void)(a)), UNUSED_8(b, c, d, e, f, g, h, i)
#define UNUSED_10(a, b, c, d, e, f, g, h, i, j) ((void)(a)), UNUSED_9(b, c, d, e, f, g, h, i, j)
#define UNUSED_11(a, b, c, d, e, f, g, h, i, j, k) \
    ((void)(a)), UNUSED_10(b, c, d, e, f, g, h, i, j, k)
#define UNUSED_12(a, b, c, d, e, f, g, h, i, j, k, l) \
    ((void)(a)), UNUSED_11(b, c, d, e, f, g, h, i, j, k, l)
#define UNUSED_13(a, b, c, d, e, f, g, h, i, j, k, l, m) \
    ((void)(a)), UNUSED_12(b, c, d, e, f, g, h, i, j, k, l, m)
#define UNUSED_14(a, b, c, d, e, f, g, h, i, j, k, l, m, n) \
    ((void)(a)), UNUSED_13(b, c, d, e, f, g, h, i, j, k, l, m, n)

#define VA_ARGS_UNUSED_IMPL_(num) UNUSED_##num
#define VA_ARGS_UNUSED_IMPL(num) VA_ARGS_UNUSED_IMPL_(num)

#define VA_NARGS_IMPL(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, N, ...) N
#define VA_NARGS(...) VA_NARGS_IMPL(__VA_ARGS__, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

#define VA_ARGS_UNUSED(...) VA_ARGS_UNUSED_IMPL(VA_NARGS(__VA_ARGS__))(__VA_ARGS__)

#endif  // !ANDROID

#endif  // CONSCRYPT_SRC_MAIN_NATIVE_MACROS_H_
