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

import static org.junit.Assert.assertEquals;
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
    private static final String OPERATOR1 = "operator 1";
    private static final String OPERATOR2 = "operator 2";
    private static LogInfo usableOp1Log1;
    private static LogInfo usableOp1Log2;
    private static LogInfo retiredOp1LogOld;
    private static LogInfo retiredOp1LogNew;
    private static LogInfo usableOp2Log;
    private static LogInfo retiredOp2Log;
    private static SignedCertificateTimestamp embeddedSCT;
    private static SignedCertificateTimestamp ocspSCT;

    /* Some test dates. By default:
     *  - The verification is occurring in January 2024;
     *  - The log list was created in December 2023;
     *  - The SCTs were generated in January 2023; and
     *  - The logs got into their state in January 2022.
     * Other dates are used to exercise edge cases.
     */
    private static final long JAN2025 = 1735725600000L;
    private static final long JAN2024 = 1704103200000L;
    private static final long DEC2023 = 1701424800000L;
    private static final long JUN2023 = 1672999200000L;
    private static final long JAN2023 = 1672567200000L;
    private static final long JAN2022 = 1641031200000L;

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
                                .setOperator(OPERATOR1)
                                .setState(LogInfo.STATE_USABLE, JAN2022)
                                .build();
        usableOp1Log2 = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x02}))
                                .setUrl("")
                                .setOperator(OPERATOR1)
                                .setState(LogInfo.STATE_USABLE, JAN2022)
                                .build();
        retiredOp1LogOld = new LogInfo.Builder()
                                   .setPublicKey(new FakePublicKey(new byte[] {0x03}))
                                   .setUrl("")
                                   .setOperator(OPERATOR1)
                                   .setState(LogInfo.STATE_RETIRED, JAN2022)
                                   .build();
        retiredOp1LogNew = new LogInfo.Builder()
                                   .setPublicKey(new FakePublicKey(new byte[] {0x06}))
                                   .setUrl("")
                                   .setOperator(OPERATOR1)
                                   .setState(LogInfo.STATE_RETIRED, JUN2023)
                                   .build();
        usableOp2Log = new LogInfo.Builder()
                               .setPublicKey(new FakePublicKey(new byte[] {0x04}))
                               .setUrl("")
                               .setOperator(OPERATOR2)
                               .setState(LogInfo.STATE_USABLE, JAN2022)
                               .build();
        retiredOp2Log = new LogInfo.Builder()
                                .setPublicKey(new FakePublicKey(new byte[] {0x05}))
                                .setUrl("")
                                .setOperator(OPERATOR2)
                                .setState(LogInfo.STATE_RETIRED, JAN2022)
                                .build();
        /* The origin of the SCT and its timestamp are used during the
         * evaluation for policy compliance. The signature is validated at the
         * previous step (see the Verifier class).
         */
        embeddedSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
                JAN2023, null, null, SignedCertificateTimestamp.Origin.EMBEDDED);
        ocspSCT = new SignedCertificateTimestamp(SignedCertificateTimestamp.Version.V1, null,
                JAN2023, null, null, SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
    }

    @Test
    public void emptyVerificationResult() throws Exception {
        PolicyImpl p = new PolicyImpl();
        VerificationResult result = new VerificationResult();

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("An empty VerificationResult", PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    public void validVerificationResult(SignedCertificateTimestamp sct) throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("Two valid SCTs from different operators", PolicyCompliance.COMPLY,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void validEmbeddedVerificationResult() throws Exception {
        validVerificationResult(embeddedSCT);
    }

    @Test
    public void validOCSPVerificationResult() throws Exception {
        validVerificationResult(ocspSCT);
    }

    @Test
    public void validEmbeddedWithRetiredVerificationResult() throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1LogNew)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("One valid, one retired SCTs from different operators",
                PolicyCompliance.COMPLY, p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void invalidOCSPWithRecentRetiredVerificationResult() throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(ocspSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1LogNew)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("One valid, one retired SCTs from different operators",
                PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    public void invalidWithRetiredVerificationResult(SignedCertificateTimestamp sct)
            throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1LogOld)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("One valid, one retired (before SCT timestamp) SCTs from different operators",
                PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void invalidEmbeddedWithRetiredVerificationResult() throws Exception {
        invalidWithRetiredVerificationResult(embeddedSCT);
    }

    @Test
    public void invalidOCSPWithRetiredVerificationResult() throws Exception {
        invalidWithRetiredVerificationResult(ocspSCT);
    }

    public void invalidOneSctVerificationResult(SignedCertificateTimestamp sct) throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("One valid SCT", PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void invalidEmbeddedOneSctVerificationResult() throws Exception {
        invalidOneSctVerificationResult(embeddedSCT);
    }

    @Test
    public void invalidOCSPOneSctVerificationResult() throws Exception {
        invalidOneSctVerificationResult(ocspSCT);
    }

    public void invalidTwoRetiredSctsVerificationResult(SignedCertificateTimestamp sct)
            throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp1LogNew)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(retiredOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("Two retired SCTs from different operators", PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void invalidEmbeddedTwoRetiredSctsVerificationResult() throws Exception {
        invalidTwoRetiredSctsVerificationResult(embeddedSCT);
    }

    @Test
    public void invalidOCSPTwoRetiredSctsVerificationResult() throws Exception {
        invalidTwoRetiredSctsVerificationResult(ocspSCT);
    }

    public void invalidTwoSctsSameOperatorVerificationResult(SignedCertificateTimestamp sct)
            throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(sct)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log2)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("Two SCTs from the same operator", PolicyCompliance.NOT_ENOUGH_DIVERSE_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void invalidEmbeddedTwoSctsSameOperatorVerificationResult() throws Exception {
        invalidTwoSctsSameOperatorVerificationResult(embeddedSCT);
    }

    @Test
    public void invalidOCSPTwoSctsSameOperatorVerificationResult() throws Exception {
        invalidTwoSctsSameOperatorVerificationResult(ocspSCT);
    }

    @Test
    public void invalidOneEmbeddedOneOCSPVerificationResult() throws Exception {
        PolicyImpl p = new PolicyImpl();

        VerifiedSCT vsct1 = new VerifiedSCT.Builder(embeddedSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp1Log1)
                                    .build();

        VerifiedSCT vsct2 = new VerifiedSCT.Builder(ocspSCT)
                                    .setStatus(VerifiedSCT.Status.VALID)
                                    .setLogInfo(usableOp2Log)
                                    .build();

        VerificationResult result = new VerificationResult();
        result.add(vsct1);
        result.add(vsct2);

        X509Certificate leaf = new FakeX509Certificate();
        assertEquals("Two valid SCTs with different origins", PolicyCompliance.NOT_ENOUGH_SCTS,
                p.doesResultConformToPolicyAt(result, leaf, JAN2024));
    }

    @Test
    public void validRecentLogStore() throws Exception {
        PolicyImpl p = new PolicyImpl();

        LogStore store = new LogStoreImpl() {
            @Override
            public long getTimestamp() {
                return DEC2023;
            }
        };
        assertTrue("A recent log list is compliant", p.isLogStoreCompliantAt(store, JAN2024));
    }

    @Test
    public void invalidFutureLogStore() throws Exception {
        PolicyImpl p = new PolicyImpl();

        LogStore store = new LogStoreImpl() {
            @Override
            public long getTimestamp() {
                return JAN2025;
            }
        };
        assertFalse("A future log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
    }

    @Test
    public void invalidOldLogStore() throws Exception {
        PolicyImpl p = new PolicyImpl();

        LogStore store = new LogStoreImpl() {
            @Override
            public long getTimestamp() {
                return JAN2023;
            }
        };
        assertFalse("A expired log list is non-compliant", p.isLogStoreCompliantAt(store, JAN2024));
    }
}
