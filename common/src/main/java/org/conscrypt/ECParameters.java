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

package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * AlgorithmParameters implementation for elliptic curves.  The only supported encoding format is
 * ASN.1, as specified in RFC 3279, section 2.3.5.  However, only named curves are supported.
 */
@Internal
public class ECParameters extends AlgorithmParametersSpi {

    private OpenSSLECGroupContext curve;

    public ECParameters() {}

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof ECGenParameterSpec) {
            String newCurveName = ((ECGenParameterSpec) algorithmParameterSpec).getName();
            OpenSSLECGroupContext newCurve = OpenSSLECGroupContext.getCurveByName(newCurveName);
            if (newCurve == null) {
                throw new InvalidParameterSpecException("Unknown EC curve name: " + newCurveName);
            }
            this.curve = newCurve;
        } else if (algorithmParameterSpec instanceof ECParameterSpec) {
            ECParameterSpec ecParamSpec = (ECParameterSpec) algorithmParameterSpec;
            try {
                OpenSSLECGroupContext newCurve = OpenSSLECGroupContext.getInstance(ecParamSpec);
                if (newCurve == null) {
                    throw new InvalidParameterSpecException("Unknown EC curve: " + ecParamSpec);
                }
                this.curve = newCurve;
            } catch (InvalidAlgorithmParameterException e) {
                throw new InvalidParameterSpecException(e.getMessage());
            }
        } else {
            throw new InvalidParameterSpecException(
                    "Only ECParameterSpec and ECGenParameterSpec are supported");
        }
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long ref = NativeCrypto.EC_KEY_parse_curve_name(bytes);
        if (ref == 0) {
            throw new IOException("Error reading ASN.1 encoding");
        }
        this.curve = new OpenSSLECGroupContext(new NativeRef.EC_GROUP(ref));
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            engineInit(bytes);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if (aClass == ECParameterSpec.class) {
            return (T) curve.getECParameterSpec();
        } else if (aClass == ECGenParameterSpec.class) {
            return (T) new ECGenParameterSpec(curve.getCurveName());
        } else {
            throw new InvalidParameterSpecException("Unsupported class: " + aClass);
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return NativeCrypto.EC_KEY_marshal_curve_name(curve.getNativeRef());
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        return "Conscrypt EC AlgorithmParameters";
    }
}
