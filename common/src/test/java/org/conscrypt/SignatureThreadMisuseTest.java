package org.conscrypt;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * These tests abuse a single Signature object across multiple threads to check for any native
 * crashes.
 */
@RunWith(JUnit4.class)
public final class SignatureThreadMisuseTest {
    private final Provider conscryptProvider = TestUtils.getConscryptProvider();

    @Before
    public void setUp() {
        Assume.assumeFalse("Skipping thread misuse test under TSAN", TestUtils.isTsan());
    }

    @Test
    public void testSha256withEcdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", conscryptProvider);
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        Signature signature = Signature.getInstance("SHA256withECDSA", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    @Test
    public void testNoneWithEcdsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", conscryptProvider);
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        Signature signature = Signature.getInstance("NONEwithECDSA", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    // We hard-code the private key to make the test run faster.
    private static final byte[] rsaPrivKeyPkcs8 = TestUtils.decodeBase64(
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGWlZEwCYGp4HD"
            + "o+6p9xHo14eAMqQqaaPqy4CNqBwepXzfOyrWygJXxyXQNE3J/HkjvkXYjuF0BVfW"
            + "nU1t58mjXn9z8FeIxgP4JlgrO/UZkp7KpnxU0foXrA73Xq57r7/8XLRtBaqBUC6p"
            + "yxwNwgLbuvOaukSpU6+EbKJfPFO0yMVYjSZEg4NhgLud87SQ/Q8xMio9NhRtWtMV"
            + "i1fTMOQtfX2ow+2ZE8eW2ScIHQZoizaIlJ/4tQDpY6ovRyPmmCP/1ypB/75d3odf"
            + "IEOMwNQS+/e1Hxo1Ui89VLt80wx63i+nI60Rf6Num+jo3OOu5QZfr/279XA1CmaQ"
            + "NJjJzKCRAgMBAAECggEATSQ1COfx4gSjYwMOfuun+3ZXLHSFhDkxls8uX+lRhlm2"
            + "Bttr/bzyzFCXVDIDTtryAgSuBVsMM6MgVkc3JddPhEnsJ5sBcCASyx+eirH20MtF"
            + "FmtJT3OaYDp6V5prIY9oiy1CvmPFvCUDAOYNMwyRMAO1Wie3LGNvj4DwZTmBFH2Q"
            + "f++d3aVo8F4VsKHbPegIpZeRSeNvTBxqr++mEPlU3U4CvmGrEGHDkInumorL1r8v"
            + "umwLgYmLTND/lIeMPu9qRP74SXU/y8BlkpBEd90FRXSRz1pvFXy//5Snd3syH0hL"
            + "ow37+LFLzI92rtDv6NJiFm45C3Qz1Dc65DsScaQ3AQKBgQD6gy9FzIoETmvvfUkP"
            + "7pYbL9tiNanTCg/QO7w2UaSqegDuXeuujer6+ZRYmHDcBgEPDM0IC6/VTfuNiJJf"
            + "SA6zEY0QuOJ8/1NWgA6WRoTIdVOqb2rQZxPGmlApwNpm2INwgdIp8R8+z1TuiZ7Q"
            + "BJGfDCyIMAg/OFNIsF2jjjWOFQKBgQDKsqdXGFLH+cfCf5D42F2RCTYW64nAq1S+"
            + "6PjaeBKDt/UWKJIVuOlIK/+NTnkomgg9uYg3hz6StuyRRB+gt6ZvmdPZfbqmw013"
            + "tjEaoajewTwTYTjiUEte3unSYC7eQdP3wozSSTj5xrJ0rzIylUArnep5oK9T75ZX"
            + "nMQ/1P6jjQKBgQCH/N6UjUv+unNtNh2LQIDLkVcOIQNnRHcBGuw4sGkrAb+vpdxi"
            + "jTeZthIJZfcd+URp3xEN5Qo2SHbdhd2vS3ZvTn+9LCAGqrOaqTlB6lX6W3ZndsQN"
            + "DWd20B3kDISCf9YaJN7pVbMYbYQ1WQ+U7GYAaKNj6m8PoovTUaoDNxdrYQKBgBW9"
            + "ZY9Ez5QdKRymO/FEm3xzxXZd2s9sUNGNASvFVw8DiujOfySPSY3xEh6gvQPqyVl9"
            + "bauu+LoZnnPSH6ZILDSqBfu8rWk3ZzagttGJZyhFB2F4uvYi8IKDXAaxRDWYT9ix"
            + "6BKhwdegRQGYzMR6F4DWFhDneAaDmtdYu/+wo4L9AoGAB2/QLydO0bicjcg/NPM6"
            + "5saPHKRcF6rtRgYkAdD24NNd/hCSsnJF2Flpm0baLp/UN/eh514rsonNQy885k+4"
            + "Y1uId7Gmwoo9+BmaEs+lz1TmSdPAvhAP12/wpqMMTwC91f+F2QZZtq32FoxeNOG4"
            + "MUlGMKiKK2f8nB6soz84zbg=");

    @Test
    public void testSha256withRsa() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", conscryptProvider);
        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(rsaPrivKeyPkcs8));

        Signature signature = Signature.getInstance("SHA256withRSA", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    @Test
    public void testSha256withRsaPss() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", conscryptProvider);
        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(rsaPrivKeyPkcs8));

        Signature signature = Signature.getInstance("SHA256withRSA/PSS", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    @Test
    public void testNoneWithRsa() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", conscryptProvider);
        PrivateKey privateKey =
                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(rsaPrivKeyPkcs8));

        Signature signature = Signature.getInstance("NONEwithRSA", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    @Test
    public void testEd25519() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", conscryptProvider);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        Signature signature = Signature.getInstance("Ed25519", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    @Test
    public void testMlDsa44() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", conscryptProvider);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        Signature signature = Signature.getInstance("ML-DSA-44", conscryptProvider);
        final byte[] message = new byte[64];
        TestUtils.stressTestAllowingExceptions(16, 100, () -> {
            signature.initSign(privateKey);
            signature.update(message);
            signature.sign();
        });
    }

    // We currently don't run these tests for SLH-DSA-SHA2-128S, because it is too slow.
}
