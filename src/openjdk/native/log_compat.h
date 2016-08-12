/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef _CONSCRYPT_LOG_COMPAT_H
#define _CONSCRYPT_LOG_COMPAT_H

#include "unused.h"

#define LOG_INFO ((void)0)

#define ALOG(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGD(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGE(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)
#define ALOGV(...) \
            VA_ARGS_UNUSED(__VA_ARGS__)

#endif /* _CONSCRYPT_LOG_COMPAT_H */
