/*
 * Copyright (C) 2024 The Android Open Source Project
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

package org.conscrypt.ct;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.conscrypt.java.security.cert.FakeX509Certificate;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

@RunWith(JUnit4.class)
public class PolicyImplTest {
    private static LogInfo usableOp1Log1;
    private static LogInfo usableOp1Log2;
    private static LogInfo retiredOp1Log;
    private static LogInfo usableOp2Log;
    private static LogInfo retiredOp2Log;
    private static SignedCertificateTimestamp embeddedSCT;

    private static class FakePublicKey implements PublicKey {
        static final long serialVersionUID = 1;
        final byte[] key;

        FakePublicKey(byte[] key) {
            this.key = key;
        }

        @Override
        public byte[] getEncoded() {
            return this.key;
        }

        @Override
        public String getAlgorithm() {
            return "";
        }

        @Override
        public String getFormat() {
            return "";
        }
    }

    @BeforeClass
    public static void setUp() {
        /* Defines LogInfo for the tests. Only a subset of the attributes are
         * expected to be used, namely the LogID (based on the public key), the
         * operator name and the log state.
         */
        usableOp1Log1 = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x01}))
                                .setUrl("")
                                .setOperator("operator 1")
                                .setState(LogInfo.STATE_USABLE)
                                .build();
        usableOp1Log2 = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x02}))
                                .setUrl("")
                                .setOperator("operator 1")
                                .setState(LogInfo.STATE_USABLE)
                                .build();
        retiredOp1Log = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x03}))
                                .setUrl("")
                                .setOperator("operator 1")
                                .setState(LogInfo.STATE_RETIRED)
                                .build();
        usableOp2Log = new LogInfo.Builder()
                               .setPublicKey(new FakePublicKey(new byte[] {0x04}))
                               .setUrl("")
                               .setOperator("operator 2")
                               .setState(LogInfo.STATE_USABLE)
                               .build();
        retiredOp2Log = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x05}))
                                .setUrl("")
                                .setOperator("operator 2")
                                .setState(LogInfo.STATE_RETIRED)
                                .build();
        /* Only the origin of the SCT is used during the evaluation for policy
         * compliance. The signature is validated at the previous step (see
         * the Verifier class).
         */
        embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null, 0,
                null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
    }

    @Test
    public void emptyVerificationResult() throws Exception {
        Policy p = new PolicyImpl();
        VerificationResult result = new VerificationResult();

        X509Certificate leaf = new FakeX509Certificate();
        assertFalse("An empty VerificationResult", p.doesResultConformToPolicy(result, leaf));
    }

    @Test
    public void validVerificationResult() throws Exception {
        Policy p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertTrue("Two valid SCTs from different operators",
                p.doesResultConformToPolicy(result, leaf));
    }

    @Test
    public void validWithRetiredVerificationResult() throws Exception {
        Policy p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1Log)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertTrue("One valid, one retired SCTs from different operators",
                p.doesResultConformToPolicy(result, leaf));
    }

    @Test
    public void invalidOneSctVerificationResult() throws Exception {
        Policy p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);

        X509Certificate leaf = new FakeX509Certificate();
        assertFalse("One valid SCT", p.doesResultConformToPolicy(result, leaf));
    }

    @Test
    public void invalidTwoSctsVerificationResult() throws Exception {
        Policy p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1Log)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertFalse("Two retired SCTs from different operators",
                p.doesResultConformToPolicy(result, leaf));
    }
}
