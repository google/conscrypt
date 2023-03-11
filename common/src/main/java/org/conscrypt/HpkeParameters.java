/*
 * Copyright 2015 The Android Open Source Project
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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.conscrypt.HpkeAlgorithmIdentifier.AEAD;
import org.conscrypt.HpkeAlgorithmIdentifier.KDF;
import org.conscrypt.HpkeAlgorithmIdentifier.KEM;
import org.conscrypt.HpkeParameterSpec.Mode;

/**
 * HPKE parameters used during ciphering operation with {@link OpenSSLCipherHpke}. This class is
 * used internally to provide the parameters needed to perform encryption/decryption or secret
 * exports with any HPKE modes (base, psk, auth, or auth_psk).
 *
 * <p>
 * The only supported encoding format is ASN.1
 */
@Internal
public final class HpkeParameters extends AlgorithmParametersSpi {

    private HpkeAlgorithmIdentifier algorithm;
    private byte[] enc;
    private byte[] info;
    private byte[] iv;
    private byte[] psk;
    private byte[] pskId;
    private byte[] authKey;
    private int l;
    private Mode mode;
    private boolean encrypting;
    private boolean exporting;

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof HpkeParameterSpec) {
            final HpkeParameterSpec hpkeSpec = (HpkeParameterSpec) algorithmParameterSpec;
            this.algorithm = hpkeSpec.getAlgorithmIdentifier();
            this.enc = hpkeSpec.getEnc();
            this.info = hpkeSpec.getInfo();
            this.iv = hpkeSpec.getIv();
            this.psk = hpkeSpec.getPsk();
            this.pskId = hpkeSpec.getPskId();
            this.authKey = hpkeSpec.getAuthKey();
            this.l = hpkeSpec.getL();
            this.mode = hpkeSpec.getMode();
            this.encrypting = hpkeSpec.isEncrypting();
            this.exporting = hpkeSpec.isExporting();
        } else {
            throw new InvalidParameterSpecException("Only HpkeParametersSpec is supported");
        }
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            final String kem =
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8");
            final String kdf =
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8");
            final String aead =
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8");
            final byte[] enc = NativeCrypto.asn1_read_octetstring(seqRef);
            final byte[] info = NativeCrypto.asn1_read_octetstring(seqRef);
            final byte[] iv = NativeCrypto.asn1_read_octetstring(seqRef);
            final byte[] psk = NativeCrypto.asn1_read_octetstring(seqRef);
            final byte[] pskId = NativeCrypto.asn1_read_octetstring(seqRef);
            final byte[] authKey = NativeCrypto.asn1_read_octetstring(seqRef);
            final int l = (int) NativeCrypto.asn1_read_uint64(seqRef);
            final Mode mode = Mode.valueOf(
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8"));
            final boolean encrypting = Boolean.parseBoolean(
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8"));
            final boolean exporting = Boolean.parseBoolean(
                new String(NativeCrypto.asn1_read_octetstring(seqRef), "UTF-8"));
            if (!NativeCrypto.asn1_read_is_empty(seqRef)
                || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }

            this.algorithm =
                new HpkeAlgorithmIdentifier(KEM.valueOf(kem), KDF.valueOf(kdf), AEAD.valueOf(aead));
            this.enc = enc;
            this.info = info;
            this.iv = iv;
            this.psk = psk;
            this.pskId = pskId;
            this.authKey = authKey;
            this.l = l;
            this.encrypting = encrypting;
            this.exporting = exporting;
            this.mode = mode;
        } finally {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            engineInit(bytes);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if (aClass != null && aClass.isAssignableFrom(HpkeParameterSpec.class)) {
            return aClass.cast(
                new HpkeParameterSpec
                    .Builder(algorithm, enc, info, iv, l, psk, pskId, authKey, mode, encrypting,
                    exporting).build());
        } else {
            throw new InvalidParameterSpecException("Unsupported class: " + aClass);
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        long seqRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbbRef);
            NativeCrypto.asn1_write_octetstring(seqRef,
                algorithm.getKem().name().getBytes("UTF-8"));
            NativeCrypto.asn1_write_octetstring(seqRef,
                algorithm.getKdf().name().getBytes("UTF-8"));
            NativeCrypto.asn1_write_octetstring(seqRef,
                algorithm.getAead().name().getBytes("UTF-8"));
            writeOptionalOctetString(seqRef, enc);
            writeOptionalOctetString(seqRef, info);
            writeOptionalOctetString(seqRef, iv);
            writeOptionalOctetString(seqRef, psk);
            writeOptionalOctetString(seqRef, pskId);
            writeOptionalOctetString(seqRef, authKey);
            NativeCrypto.asn1_write_uint64(seqRef, l);
            NativeCrypto.asn1_write_octetstring(seqRef,
                mode.name().getBytes("UTF-8"));
            NativeCrypto.asn1_write_octetstring(seqRef,
                String.valueOf(encrypting).getBytes("UTF-8"));
            NativeCrypto.asn1_write_octetstring(seqRef,
                String.valueOf(exporting).getBytes("UTF-8"));
            return NativeCrypto.asn1_write_finish(cbbRef);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } finally {
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbbRef);
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        return "Conscrypt HPKE AlgorithmParameters";
    }

    private void writeOptionalOctetString(long seqRef, byte[] value) throws IOException {
        if (value == null) {
            NativeCrypto.asn1_write_null(seqRef);
        } else {
            NativeCrypto.asn1_write_octetstring(seqRef, value);
        }
    }
}
