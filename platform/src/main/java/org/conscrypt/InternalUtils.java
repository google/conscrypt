/*
 * Copyright 2017 The Android Open Source Project
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

import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

/**
 * Helper to initialize the JNI libraries. This version runs when compiled
 * as part of the platform.
 *
 * @hide
 */
@Internal
public final class InternalUtils {
    private final static char[] DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    private InternalUtils() {}

    public static PublicKey logKeyToPublicKey(byte[] logKey) throws NoSuchAlgorithmException {
        return new OpenSSLKey(NativeCrypto.d2i_PUBKEY(logKey)).getPublicKey();
    }

    public static PublicKey readPublicKeyPem(InputStream pem) throws InvalidKeyException, NoSuchAlgorithmException {
        return OpenSSLKey.fromPublicKeyPemInputStream(pem).getPublicKey();
    }

    public static byte[] getOcspSingleExtension(
            byte[] ocspResponse, String oid, long x509Ref, long issuerX509Ref) {
        return NativeCrypto.get_ocsp_single_extension(ocspResponse, oid, x509Ref, issuerX509Ref);
    }

    public static String bytesToHexString(byte[] bytes) {
        char[] buf = new char[bytes.length * 2];
        int c = 0;
        for (byte b : bytes) {
            buf[c++] = DIGITS[(b >> 4) & 0xf];
            buf[c++] = DIGITS[b & 0xf];
        }
        return new String(buf);
    }

    public static String intToHexString(int i, int minWidth) {
        int bufLen = 8;  // Max number of hex digits in an int
        char[] buf = new char[bufLen];
        int cursor = bufLen;

        do {
            buf[--cursor] = DIGITS[i & 0xf];
        } while ((i >>>= 4) != 0 || (bufLen - cursor < minWidth));

        return new String(buf, cursor, bufLen - cursor);
    }
}
