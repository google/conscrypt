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

package org.conscrypt;

public final class EvpMdRef {
    public static final class MD5 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("md5");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA1 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha1");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA224 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha224");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA256 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha256");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA384 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha384");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }

    public static final class SHA512 {
        public static final long EVP_MD = NativeCrypto.EVP_get_digestbyname("sha512");
        public static final int SIZE = NativeCrypto.EVP_MD_size(EVP_MD);
    }
}
