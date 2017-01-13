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

#ifndef CONSCRYPT_TRACE_H_
#define CONSCRYPT_TRACE_H_

#include <cstddef>
#include "macros.h"

namespace conscrypt {

class Trace {
private:
    Trace() {}
    ~Trace() {}

public:
    static constexpr bool kWithJniTrace = false;
    static constexpr bool kWithJniTraceMd = false;
    static constexpr bool kWithJniTraceData = false;

    /*
     * To print create a pcap-style dump you can take the log output and
     * pipe it through text2pcap.
     *
     * For example, if you were interested in ssl=0x12345678, you would do:
     *
     *  address=0x12345678
     *  awk "match(\$0,/ssl=$address SSL_DATA: (.*)\$/,a){print a[1]}" | text2pcap -T 443,1337 -t
     * '%s.' -n -D - $address.pcapng
     */
    static constexpr bool kWithJniTracePackets = false;

    /*
     * How to use this for debugging with Wireshark:
     *
     * 1. Pull lines from logcat to a file that have "KEY_LINE:" and remove the
     *    prefix up to and including "KEY_LINE: " so they look like this
     *    (without the quotes):
     *     "RSA 3b8...184 1c5...aa0" <CR>
     *     "CLIENT_RANDOM 82e...f18b 1c5...aa0" <CR>
     *     <etc>
     *    Follows the format defined at
     *    https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
     * 2. Start Wireshark
     * 3. Go to Edit -> Preferences -> SSL -> (Pre-)Master-Key log and fill in
     *    the file you put the lines in above.
     * 4. Follow the stream that corresponds to the desired "Session-ID" in
     *    the Server Hello.
     */
    static constexpr bool kWithJniTraceKeys = false;

    // don't overwhelm logcat
    static constexpr std::size_t kWithJniTraceDataChunkSize = 512;
};  // class Trace

}  // namespace conscrypt

#define JNI_TRACE(...)                               \
    if (conscrypt::Trace::kWithJniTrace) {           \
        ALOG(LOG_INFO, LOG_TAG "-jni", __VA_ARGS__); \
    }
#define JNI_TRACE_MD(...)                            \
    if (conscrypt::Trace::kWithJniTraceMd) {         \
        ALOG(LOG_INFO, LOG_TAG "-jni", __VA_ARGS__); \
    }
#define JNI_TRACE_KEYS(...)                          \
    if (conscrypt::Trace::kWithJniTraceKeys) {       \
        ALOG(LOG_INFO, LOG_TAG "-jni", __VA_ARGS__); \
    }
#define JNI_TRACE_PACKET_DATA(ssl, dir, data, len)    \
    if (conscrypt::Trace::kWithJniTracePackets) {     \
        debug_print_packet_data(ssl, dir, data, len); \
    }

#endif  // CONSCRYPT_SCOPEDSSLBIO_H_
