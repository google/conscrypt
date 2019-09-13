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

import static org.conscrypt.TestUtils.installConscryptAsDefaultProvider;

import org.conscrypt.ct.CTVerifierTest;
import org.conscrypt.ct.SerializationTest;
import org.conscrypt.java.security.AlgorithmParameterGeneratorTestDH;
import org.conscrypt.java.security.AlgorithmParameterGeneratorTestDSA;
import org.conscrypt.java.security.AlgorithmParametersPSSTest;
import org.conscrypt.java.security.AlgorithmParametersTestAES;
import org.conscrypt.java.security.AlgorithmParametersTestDES;
import org.conscrypt.java.security.AlgorithmParametersTestDESede;
import org.conscrypt.java.security.AlgorithmParametersTestDH;
import org.conscrypt.java.security.AlgorithmParametersTestDSA;
import org.conscrypt.java.security.AlgorithmParametersTestEC;
import org.conscrypt.java.security.AlgorithmParametersTestGCM;
import org.conscrypt.java.security.AlgorithmParametersTestOAEP;
import org.conscrypt.java.security.KeyFactoryTestDH;
import org.conscrypt.java.security.KeyFactoryTestDSA;
import org.conscrypt.java.security.KeyFactoryTestEC;
import org.conscrypt.java.security.KeyFactoryTestRSA;
import org.conscrypt.java.security.KeyPairGeneratorTest;
import org.conscrypt.java.security.KeyPairGeneratorTestDH;
import org.conscrypt.java.security.KeyPairGeneratorTestDSA;
import org.conscrypt.java.security.KeyPairGeneratorTestRSA;
import org.conscrypt.java.security.MessageDigestTest;
import org.conscrypt.java.security.SignatureTest;
import org.conscrypt.java.security.cert.CertificateFactoryTest;
import org.conscrypt.java.security.cert.X509CRLTest;
import org.conscrypt.java.security.cert.X509CertificateTest;
import org.conscrypt.javax.crypto.AeadCipherTest;
import org.conscrypt.javax.crypto.CipherBasicsTest;
import org.conscrypt.javax.crypto.CipherTest;
import org.conscrypt.javax.crypto.ECDHKeyAgreementTest;
import org.conscrypt.javax.crypto.KeyGeneratorTest;
import org.conscrypt.javax.net.ssl.HttpsURLConnectionTest;
import org.conscrypt.javax.net.ssl.KeyManagerFactoryTest;
import org.conscrypt.javax.net.ssl.KeyStoreBuilderParametersTest;
import org.conscrypt.javax.net.ssl.SNIHostNameTest;
import org.conscrypt.javax.net.ssl.SSLContextTest;
import org.conscrypt.javax.net.ssl.SSLEngineTest;
import org.conscrypt.javax.net.ssl.SSLEngineVersionCompatibilityTest;
import org.conscrypt.javax.net.ssl.SSLParametersTest;
import org.conscrypt.javax.net.ssl.SSLServerSocketFactoryTest;
import org.conscrypt.javax.net.ssl.SSLServerSocketTest;
import org.conscrypt.javax.net.ssl.SSLSessionContextTest;
import org.conscrypt.javax.net.ssl.SSLSessionTest;
import org.conscrypt.javax.net.ssl.SSLSocketFactoryTest;
import org.conscrypt.javax.net.ssl.SSLSocketTest;
import org.conscrypt.javax.net.ssl.SSLSocketVersionCompatibilityTest;
import org.conscrypt.javax.net.ssl.TrustManagerFactoryTest;
import org.conscrypt.javax.net.ssl.X509KeyManagerTest;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        // org.conscrypt tests
        CertPinManagerTest.class,
        ChainStrengthAnalyzerTest.class,
        TrustManagerImplTest.class,
        // org.conscrypt.ct tests
        CTVerifierTest.class,
        SerializationTest.class,
        // java.security tests
        CertificateFactoryTest.class,
        X509CertificateTest.class,
        X509CRLTest.class,
        AlgorithmParameterGeneratorTestDH.class,
        AlgorithmParameterGeneratorTestDSA.class,
        AlgorithmParametersPSSTest.class,
        AlgorithmParametersTestAES.class,
        AlgorithmParametersTestDES.class,
        AlgorithmParametersTestDESede.class,
        AlgorithmParametersTestDH.class,
        AlgorithmParametersTestDSA.class,
        AlgorithmParametersTestEC.class,
        AlgorithmParametersTestGCM.class,
        AlgorithmParametersTestOAEP.class,
        KeyFactoryTestDH.class,
        KeyFactoryTestDSA.class,
        KeyFactoryTestEC.class,
        KeyFactoryTestRSA.class,
        KeyPairGeneratorTest.class,
        KeyPairGeneratorTestDH.class,
        KeyPairGeneratorTestDSA.class,
        KeyPairGeneratorTestRSA.class,
        MessageDigestTest.class,
        SignatureTest.class,
        // javax.crypto tests
        AeadCipherTest.class,
        CipherBasicsTest.class,
        CipherTest.class,
        ECDHKeyAgreementTest.class,
        KeyGeneratorTest.class,
        // javax.net.ssl tests
        HttpsURLConnectionTest.class,
        KeyManagerFactoryTest.class,
        KeyStoreBuilderParametersTest.class,
        SNIHostNameTest.class,
        SSLContextTest.class,
        SSLEngineTest.class,
        SSLEngineVersionCompatibilityTest.class,
        SSLParametersTest.class,
        SSLServerSocketFactoryTest.class,
        SSLServerSocketTest.class,
        SSLSessionContextTest.class,
        SSLSessionTest.class,
        SSLSocketFactoryTest.class,
        SSLSocketTest.class,
        SSLSocketVersionCompatibilityTest.class,
        TrustManagerFactoryTest.class,
        X509KeyManagerTest.class,
})
public class ConscryptSuite {

    @BeforeClass
    public static void setupStatic() {
        installConscryptAsDefaultProvider();
    }

}
