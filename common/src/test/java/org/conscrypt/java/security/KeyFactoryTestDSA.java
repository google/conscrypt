/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.conscrypt.java.security;

import java.security.KeyPair;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyFactoryTestDSA extends
        AbstractKeyFactoryTest<DSAPublicKeySpec, DSAPrivateKeySpec> {

    public KeyFactoryTestDSA() {
        super("DSA", DSAPublicKeySpec.class, DSAPrivateKeySpec.class);
    }

    @Override
    protected void check(KeyPair keyPair) throws Exception {
        new SignatureHelper("DSA").test(keyPair);
    }
}
