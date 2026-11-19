/*
 * Copyright (C) 2026 The Android Open Source Project
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
package org.conscrypt.tlswire.handshake;

import org.conscrypt.tlswire.util.IoUtils;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * {@code signature_algorithms} {@link HelloExtension} from RFC 5246 section 7.4.1.4.1 and RFC 8446
 * section 4.2.3.
 */
public class SignatureAlgorithmsHelloExtension extends HelloExtension {
    public List<String> supported;
    public boolean wellFormed;

    @Override
    protected void parseData() throws IOException {
        byte[] signatureAlgorithmsListBytes = IoUtils.readTlsVariableLengthByteVector(
                new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
        ByteArrayInputStream signatureAlgorithmsListIn =
                new ByteArrayInputStream(signatureAlgorithmsListBytes);
        DataInputStream in = new DataInputStream(signatureAlgorithmsListIn);
        wellFormed = (signatureAlgorithmsListIn.available() % 2) == 0;
        supported = new ArrayList<String>(signatureAlgorithmsListIn.available() / 2);
        while (signatureAlgorithmsListIn.available() >= 2) {
            int schemeId = in.readUnsignedShort();
            supported.add(signatureSchemeToName(schemeId));
        }
    }

    private static String signatureSchemeToName(int schemeId) {
        switch (schemeId) {
            case 0x0201:
                return "rsa_pkcs1_sha1";
            case 0x0203:
                return "ecdsa_sha1";
            case 0x0401:
                return "rsa_pkcs1_sha256";
            case 0x0403:
                return "ecdsa_secp256r1_sha256";
            case 0x0501:
                return "rsa_pkcs1_sha384";
            case 0x0503:
                return "ecdsa_secp384r1_sha384";
            case 0x0601:
                return "rsa_pkcs1_sha512";
            case 0x0603:
                return "ecdsa_secp521r1_sha512";
            case 0x0804:
                return "rsa_pss_rsae_sha256";
            case 0x0805:
                return "rsa_pss_rsae_sha384";
            case 0x0806:
                return "rsa_pss_rsae_sha512";
            case 0x0807:
                return "ed25519";
            case 0x0808:
                return "ed448";
            case 0x0809:
                return "rsa_pss_pss_sha256";
            case 0x080a:
                return "rsa_pss_pss_sha384";
            case 0x080b:
                return "rsa_pss_pss_sha512";
            case 0x0904:
                return "mldsa44";
            case 0x0905:
                return "mldsa65";
            case 0x0906:
                return "mldsa87";
            default:
                return String.format("0x%04x", schemeId);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb =
                new StringBuilder("HelloExtension{type: signature_algorithms, wellFormed: ");
        sb.append(wellFormed);
        sb.append(", supported: ");
        sb.append(supported);
        sb.append('}');
        return sb.toString();
    }
}
