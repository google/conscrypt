/*
 * Copyright (C) 2018 The Android Open Source Project
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

import static org.conscrypt.TestUtils.installConscryptAsDefaultProvider;

import org.conscrypt.javax.crypto.CipherBasicsTest;
import org.conscrypt.javax.crypto.ECDHKeyAgreementTest;
import org.conscrypt.javax.crypto.KeyGeneratorTest;
import org.conscrypt.javax.net.ssl.HttpsURLConnectionTest;
import org.conscrypt.javax.net.ssl.KeyManagerFactoryTest;
import org.conscrypt.javax.net.ssl.KeyStoreBuilderParametersTest;
import org.conscrypt.javax.net.ssl.SNIHostNameTest;
import org.conscrypt.javax.net.ssl.SSLContextTest;
import org.conscrypt.javax.net.ssl.SSLEngineTest;
import org.conscrypt.javax.net.ssl.SSLParametersTest;
import org.conscrypt.javax.net.ssl.SSLServerSocketFactoryTest;
import org.conscrypt.javax.net.ssl.SSLServerSocketTest;
import org.conscrypt.javax.net.ssl.SSLSessionContextTest;
import org.conscrypt.javax.net.ssl.SSLSessionTest;
import org.conscrypt.javax.net.ssl.SSLSocketFactoryTest;
import org.conscrypt.javax.net.ssl.SSLSocketTest;
import org.conscrypt.javax.net.ssl.TrustManagerFactoryTest;
import org.conscrypt.javax.net.ssl.X509KeyManagerTest;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        // javax.crypto tests
        CipherBasicsTest.class,
        ECDHKeyAgreementTest.class,
        KeyGeneratorTest.class,
        // javax.net.ssl tests
        HttpsURLConnectionTest.class,
        KeyManagerFactoryTest.class,
        KeyStoreBuilderParametersTest.class,
        SNIHostNameTest.class,
        SSLContextTest.class,
        SSLEngineTest.class,
        SSLParametersTest.class,
        SSLServerSocketFactoryTest.class,
        SSLServerSocketTest.class,
        SSLSessionContextTest.class,
        SSLSessionTest.class,
        SSLSocketFactoryTest.class,
        SSLSocketTest.class,
        TrustManagerFactoryTest.class,
        X509KeyManagerTest.class,
})
public class ConscryptJava6Suite {

    @BeforeClass
    public static void setupStatic() {
        installConscryptAsDefaultProvider();
    }

}
