/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef SCOPED_UTF_CHARS_H_included
#define SCOPED_UTF_CHARS_H_included

#include <string.h>
#include "Errors.h"

// A smart pointer that provides read-only access to a Java string's UTF chars.
// Unlike GetStringUTFChars, we throw NullPointerException rather than abort if
// passed a null jstring, and c_str will return nullptr.
// This makes the correct idiom very simple:
//
//   ScopedUtfChars name(env, java_name);
//   if (name.c_str() == nullptr) {
//     return nullptr;
//   }
class ScopedUtfChars {
public:
    ScopedUtfChars(JNIEnv* env, jstring s) : env_(env), string_(s) {
        if (s == nullptr) {
            utf_chars_ = nullptr;
            conscrypt::Errors::jniThrowNullPointerException(env, nullptr);
        } else {
            utf_chars_ = env->GetStringUTFChars(s, nullptr);
        }
    }

    ~ScopedUtfChars() {
        if (utf_chars_) {
            env_->ReleaseStringUTFChars(string_, utf_chars_);
        }
    }

    const char* c_str() const {
        return utf_chars_;
    }

    size_t size() const {
        return strlen(utf_chars_);
    }

    const char& operator[](size_t n) const {
        return utf_chars_[n];
    }

private:
    JNIEnv* env_;
    jstring string_;
    const char* utf_chars_;

    // Disallow copy and assignment.
    ScopedUtfChars(const ScopedUtfChars&);
    void operator=(const ScopedUtfChars&);
};

#endif  // SCOPED_UTF_CHARS_H_included
