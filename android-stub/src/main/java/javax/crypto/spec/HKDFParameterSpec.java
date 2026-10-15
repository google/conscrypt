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

package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

import javax.crypto.SecretKey;

@SuppressWarnings({"unused", "DoNotCallSuggester"})
public interface HKDFParameterSpec extends AlgorithmParameterSpec {
    final class Builder {
        private Builder() {}

        public Extract extractOnly() {
            throw new UnsupportedOperationException("Stub!");
        }

        public ExtractThenExpand thenExpand(byte[] info, int length) {
            throw new UnsupportedOperationException("Stub!");
        }

        public Builder addIKM(SecretKey ikm) {
            throw new UnsupportedOperationException("Stub!");
        }

        public Builder addIKM(byte[] ikm) {
            throw new UnsupportedOperationException("Stub!");
        }

        public Builder addSalt(SecretKey salt) {
            throw new UnsupportedOperationException("Stub!");
        }

        public Builder addSalt(byte[] salt) {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    static Builder ofExtract() {
        throw new UnsupportedOperationException("Stub!");
    }

    static Expand expandOnly(SecretKey prk, byte[] info, int length) {
        throw new UnsupportedOperationException("Stub!");
    }

    final class Extract implements HKDFParameterSpec {
        private Extract() {}

        public List<SecretKey> ikms() {
            throw new UnsupportedOperationException("Stub!");
        }

        public List<SecretKey> salts() {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    final class Expand implements HKDFParameterSpec {
        private Expand() {}

        public SecretKey prk() {
            throw new UnsupportedOperationException("Stub!");
        }

        public byte[] info() {
            throw new UnsupportedOperationException("Stub!");
        }

        public int length() {
            throw new UnsupportedOperationException("Stub!");
        }
    }

    final class ExtractThenExpand implements HKDFParameterSpec {
        private ExtractThenExpand() {}

        public List<SecretKey> ikms() {
            throw new UnsupportedOperationException("Stub!");
        }

        public List<SecretKey> salts() {
            throw new UnsupportedOperationException("Stub!");
        }

        public byte[] info() {
            throw new UnsupportedOperationException("Stub!");
        }

        public int length() {
            throw new UnsupportedOperationException("Stub!");
        }
    }
}
