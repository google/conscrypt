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

#ifndef CONSCRYPT_COMPAT_H_
#define CONSCRYPT_COMPAT_H_

#if defined(ANDROID) && !defined(CONSCRYPT_OPENJDK)
// We want the XSI-compliant strerror_r (it's more portable across NDK versions,
// and the only one available until android-23), not the GNU one. We haven't
// actually defined _GNU_SOURCE ourselves, but the compiler adds it
// automatically when building C++.
//
// Including this header out of the normal order to make sure we import it the
// right way.
#undef _GNU_SOURCE
#include <string.h>

// OTOH, we need to have _GNU_SOURCE defined to pick up asprintf from stdio.h.
#define _GNU_SOURCE
#include <stdio.h>

#include <android/log.h>

#else /* !ANDROID || CONSCRYPT_OPENJDK */

#include <stdio.h>
#include <string.h>

#endif /* !ANDROID || CONSCRYPT_OPENJDK */

#ifdef _WIN32

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <winsock2.h>
#include <cstddef>

// NOLINTNEXTLINE(runtime/int)
typedef long ssize_t;
#define strerror_r(errnum, buf, buflen) strerror_s(buf, buflen, errnum)
#define strcasecmp _stricmp

// Windows doesn't define this either *sigh*...
inline int vasprintf(char **ret, const char *format, va_list args) {
    va_list copy;
    va_copy(copy, args);
    *ret = nullptr;

    int count = vsnprintf(nullptr, 0, format, args);
    if (count >= 0) {
        char *buffer = static_cast<char *>(malloc((std::size_t)count + 1));
        if (buffer == nullptr) {
            count = -1;
        } else if ((count = vsnprintf(buffer, static_cast<std::size_t>(count + 1), format, copy)) <
                   0) {
            free(buffer);
        } else {
            *ret = buffer;
        }
    }
    va_end(copy);  // Each va_start() or va_copy() needs a va_end()

    return count;
}

inline int asprintf(char **strp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vasprintf(strp, fmt, ap);
    va_end(ap);
    return r;
}

inline int gettimeofday(struct timeval *tp, struct timezone *) {
    // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing
    // zero's
    // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
    // until 00:00:00 January 1, 1970
    static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

    SYSTEMTIME system_time;
    FILETIME file_time;
    uint64_t time;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    time = ((uint64_t)file_time.dwLowDateTime);
    time += ((uint64_t)file_time.dwHighDateTime) << 32;

    tp->tv_sec = static_cast<long>((time - EPOCH) / 10000000L);  // NOLINT(runtime/int)
    tp->tv_usec = static_cast<long>(system_time.wMilliseconds * 1000);  // NOLINT(runtime/int)
    return 0;
}
#endif  // _WIN32

#endif  // CONSCRYPT_COMPAT_H_
