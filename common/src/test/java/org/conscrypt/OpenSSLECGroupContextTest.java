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

package org.conscrypt;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertThrows;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/** Unit tests for {@link OpenSSLECGroupContext}. */
@RunWith(JUnit4.class)
public class OpenSSLECGroupContextTest {
    // NIST P-224 (secp224r1) parameters
    private static final BigInteger P224_P =
            new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16);
    private static final BigInteger P224_A = P224_P.subtract(BigInteger.valueOf(3));
    private static final BigInteger P224_B =
            new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16);
    private static final BigInteger P224_X =
            new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16);
    private static final BigInteger P224_Y =
            new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16);
    private static final BigInteger P224_ORDER =
            new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16);
    private static final int P224_COFACTOR = 1;

    // NIST P-256 (prime256v1 / secp256r1) parameters
    private static final BigInteger P256_P =
            new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger P256_A = P256_P.subtract(BigInteger.valueOf(3));
    private static final BigInteger P256_B =
            new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger P256_X =
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    private static final BigInteger P256_Y =
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
    private static final BigInteger P256_ORDER =
            new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    private static final int P256_COFACTOR = 1;

    // NIST P-384 (secp384r1) parameters
    private static final BigInteger P384_P =
            new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffff"
                           + "f0000000000000000ffffffff",
                           16);
    private static final BigInteger P384_A = P384_P.subtract(BigInteger.valueOf(3));
    private static final BigInteger P384_B =
            new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398"
                           + "d8a2ed19d2a85c8edd3ec2aef",
                           16);
    private static final BigInteger P384_X =
            new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25"
                           + "dbf55296c3a545e3872760ab7",
                           16);
    private static final BigInteger P384_Y =
            new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1c"
                           + "e1d7e819d7a431d7c90ea0e5f",
                           16);
    private static final BigInteger P384_ORDER =
            new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db"
                           + "248b0a77aecec196accc52973",
                           16);
    private static final int P384_COFACTOR = 1;

    // NIST P-521 (secp521r1) parameters
    private static final BigInteger P521_P =
            new BigInteger("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                           + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                           16);
    private static final BigInteger P521_A = P521_P.subtract(BigInteger.valueOf(3));
    private static final BigInteger P521_B =
            new BigInteger("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193"
                           + "951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
                           16);
    private static final BigInteger P521_X =
            new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5"
                           + "e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
                           16);
    private static final BigInteger P521_Y =
            new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee"
                           + "72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
                           16);
    private static final BigInteger P521_ORDER =
            new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa518"
                           + "68783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
                           16);
    private static final int P521_COFACTOR = 1;

    // NIST P-192 (secp192r1) parameters (192-bit arbitrary curve)
    private static final BigInteger P192_P =
            new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16);
    private static final BigInteger P192_A =
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16);
    private static final BigInteger P192_B =
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16);
    private static final BigInteger P192_X =
            new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16);
    private static final BigInteger P192_Y =
            new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16);
    private static final BigInteger P192_ORDER =
            new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16);
    private static final int P192_COFACTOR = 1;

    @BeforeClass
    public static void setUp() {
        TestUtils.assumeAllowsUnsignedCrypto();
    }

    // --- getCurveByName Tests ---

    @Test
    public void getCurveByName_standardNistCurves_returnsStaticInstances() {
        // Arrange & Act
        OpenSSLECGroupContext p224 = OpenSSLECGroupContext.getCurveByName("secp224r1");
        OpenSSLECGroupContext p256 = OpenSSLECGroupContext.getCurveByName("prime256v1");
        OpenSSLECGroupContext p384 = OpenSSLECGroupContext.getCurveByName("secp384r1");
        OpenSSLECGroupContext p521 = OpenSSLECGroupContext.getCurveByName("secp521r1");

        // Assert: returns static final instances
        assertThat(p224).isSameInstanceAs(OpenSSLECGroupContext.SECP224R1);
        assertThat(p224.getCurveName()).isEqualTo("secp224r1");
        assertThat(p224.getNativeRef()).isNotNull();

        assertThat(p256).isSameInstanceAs(OpenSSLECGroupContext.PRIME256V1);
        assertThat(p256.getCurveName()).isEqualTo("prime256v1");
        assertThat(p256.getNativeRef()).isNotNull();

        assertThat(p384).isSameInstanceAs(OpenSSLECGroupContext.SECP384R1);
        assertThat(p384.getCurveName()).isEqualTo("secp384r1");
        assertThat(p384.getNativeRef()).isNotNull();

        assertThat(p521).isSameInstanceAs(OpenSSLECGroupContext.SECP521R1);
        assertThat(p521.getCurveName()).isEqualTo("secp521r1");
        assertThat(p521.getNativeRef()).isNotNull();
    }

    @Test
    public void getCurveByName_aliasSecp256r1_resolvesToPrime256v1() {
        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getCurveByName("secp256r1");

        // Assert
        assertThat(group).isSameInstanceAs(OpenSSLECGroupContext.PRIME256V1);
        assertThat(group.getCurveName()).isEqualTo("prime256v1");
    }

    @Test
    public void getCurveByName_oidAliases_resolveToStandardCurves() {
        // Act & Assert
        // 1.3.132.0.33 -> secp224r1
        OpenSSLECGroupContext group224 = OpenSSLECGroupContext.getCurveByName("1.3.132.0.33");
        assertThat(group224).isSameInstanceAs(OpenSSLECGroupContext.SECP224R1);
        assertThat(group224.getCurveName()).isEqualTo("secp224r1");

        // 1.3.132.0.34 -> secp384r1
        OpenSSLECGroupContext group384 = OpenSSLECGroupContext.getCurveByName("1.3.132.0.34");
        assertThat(group384).isSameInstanceAs(OpenSSLECGroupContext.SECP384R1);
        assertThat(group384.getCurveName()).isEqualTo("secp384r1");

        // 1.3.132.0.35 -> secp521r1
        OpenSSLECGroupContext group521 = OpenSSLECGroupContext.getCurveByName("1.3.132.0.35");
        assertThat(group521).isSameInstanceAs(OpenSSLECGroupContext.SECP521R1);
        assertThat(group521.getCurveName()).isEqualTo("secp521r1");

        // 1.2.840.10045.3.1.7 -> prime256v1
        OpenSSLECGroupContext group256 =
                OpenSSLECGroupContext.getCurveByName("1.2.840.10045.3.1.7");
        assertThat(group256).isSameInstanceAs(OpenSSLECGroupContext.PRIME256V1);
        assertThat(group256.getCurveName()).isEqualTo("prime256v1");
    }

    @Test
    public void getCurveByName_unknownCurveName_returnsNull() {
        // Act & Assert
        assertThat(OpenSSLECGroupContext.getCurveByName("non_existent_curve")).isNull();
        assertThat(OpenSSLECGroupContext.getCurveByName("")).isNull();
        assertThat(OpenSSLECGroupContext.getCurveByName("invalid_12345")).isNull();
    }

    @Test
    public void getCurveByName_nullCurveName_throwsNullPointerException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> OpenSSLECGroupContext.getCurveByName(null));
    }

    // --- Constructor & getNativeRef Tests ---

    @Test
    public void constructor_storesAndReturnsNativeRef() {
        // Arrange
        OpenSSLECGroupContext original = OpenSSLECGroupContext.getCurveByName("prime256v1");
        NativeRef.EC_GROUP nativeRef = original.getNativeRef();

        // Act
        OpenSSLECGroupContext context = new OpenSSLECGroupContext(nativeRef);

        // Assert
        assertThat(context.getNativeRef()).isSameInstanceAs(nativeRef);
        assertThat(context.getCurveName()).isEqualTo("prime256v1");
    }

    // --- equals & hashCode Contract Tests ---

    @Test
    public void equals_alwaysThrowsIllegalArgumentException() {
        // Arrange
        OpenSSLECGroupContext group1 = OpenSSLECGroupContext.getCurveByName("prime256v1");
        OpenSSLECGroupContext group2 = OpenSSLECGroupContext.getCurveByName("prime256v1");
        Object sameGroup = group1;
        Object otherType = "different_type";

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> group1.equals(sameGroup));
        assertThrows(IllegalArgumentException.class, () -> group1.equals(group2));
        assertThrows(IllegalArgumentException.class, () -> group1.equals(null));
        assertThrows(IllegalArgumentException.class, () -> group1.equals(otherType));
    }

    @Test
    public void hashCode_returnsConsistentValue() {
        // Arrange
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getCurveByName("prime256v1");

        // Act
        int hash1 = group.hashCode();
        int hash2 = group.hashCode();

        // Assert
        assertThat(hash1).isEqualTo(hash2);
    }

    // --- getECParameterSpec Tests ---

    @Test
    public void getECParameterSpec_secp224r1_returnsValidParameters() {
        // Arrange
        OpenSSLECGroupContext group = OpenSSLECGroupContext.SECP224R1;

        // Act
        ECParameterSpec spec = group.getECParameterSpec();

        // Assert
        assertThat(spec).isNotNull();
        assertThat(spec.getCofactor()).isEqualTo(P224_COFACTOR);
        assertThat(spec.getOrder()).isEqualTo(P224_ORDER);

        EllipticCurve curve = spec.getCurve();
        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        ECFieldFp field = (ECFieldFp) curve.getField();
        assertThat(field.getP()).isEqualTo(P224_P);
        assertThat(curve.getA()).isEqualTo(P224_A);
        assertThat(curve.getB()).isEqualTo(P224_B);

        ECPoint generator = spec.getGenerator();
        assertThat(generator.getAffineX()).isEqualTo(P224_X);
        assertThat(generator.getAffineY()).isEqualTo(P224_Y);
    }

    @Test
    public void getECParameterSpec_prime256v1_returnsValidParameters() {
        // Arrange
        OpenSSLECGroupContext group = OpenSSLECGroupContext.PRIME256V1;

        // Act
        ECParameterSpec spec = group.getECParameterSpec();

        // Assert
        assertThat(spec).isNotNull();
        assertThat(spec.getCofactor()).isEqualTo(P256_COFACTOR);
        assertThat(spec.getOrder()).isEqualTo(P256_ORDER);

        EllipticCurve curve = spec.getCurve();
        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        ECFieldFp field = (ECFieldFp) curve.getField();
        assertThat(field.getP()).isEqualTo(P256_P);
        assertThat(curve.getA()).isEqualTo(P256_A);
        assertThat(curve.getB()).isEqualTo(P256_B);

        ECPoint generator = spec.getGenerator();
        assertThat(generator.getAffineX()).isEqualTo(P256_X);
        assertThat(generator.getAffineY()).isEqualTo(P256_Y);
    }

    @Test
    public void getECParameterSpec_secp384r1_returnsValidParameters() {
        // Arrange
        OpenSSLECGroupContext group = OpenSSLECGroupContext.SECP384R1;

        // Act
        ECParameterSpec spec = group.getECParameterSpec();

        // Assert
        assertThat(spec).isNotNull();
        assertThat(spec.getCofactor()).isEqualTo(P384_COFACTOR);
        assertThat(spec.getOrder()).isEqualTo(P384_ORDER);

        EllipticCurve curve = spec.getCurve();
        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        ECFieldFp field = (ECFieldFp) curve.getField();
        assertThat(field.getP()).isEqualTo(P384_P);
        assertThat(curve.getA()).isEqualTo(P384_A);
        assertThat(curve.getB()).isEqualTo(P384_B);

        ECPoint generator = spec.getGenerator();
        assertThat(generator.getAffineX()).isEqualTo(P384_X);
        assertThat(generator.getAffineY()).isEqualTo(P384_Y);
    }

    @Test
    public void getECParameterSpec_secp521r1_returnsValidParameters() {
        // Arrange
        OpenSSLECGroupContext group = OpenSSLECGroupContext.SECP521R1;

        // Act
        ECParameterSpec spec = group.getECParameterSpec();

        // Assert
        assertThat(spec).isNotNull();
        assertThat(spec.getCofactor()).isEqualTo(P521_COFACTOR);
        assertThat(spec.getOrder()).isEqualTo(P521_ORDER);

        EllipticCurve curve = spec.getCurve();
        assertThat(curve.getField()).isInstanceOf(ECFieldFp.class);
        ECFieldFp field = (ECFieldFp) curve.getField();
        assertThat(field.getP()).isEqualTo(P521_P);
        assertThat(curve.getA()).isEqualTo(P521_A);
        assertThat(curve.getB()).isEqualTo(P521_B);

        ECPoint generator = spec.getGenerator();
        assertThat(generator.getAffineX()).isEqualTo(P521_X);
        assertThat(generator.getAffineY()).isEqualTo(P521_Y);
    }

    // --- getInstance(ECParameterSpec) Named Curve Recognition Tests ---

    @Test
    public void getInstance_fromECParameterSpec_roundTripMatchesOriginalCurve()
            throws InvalidAlgorithmParameterException {
        String[] curveNames = new String[] {"secp224r1", "prime256v1", "secp384r1", "secp521r1"};

        for (String name : curveNames) {
            // Arrange
            OpenSSLECGroupContext group = OpenSSLECGroupContext.getCurveByName(name);
            ECParameterSpec spec = group.getECParameterSpec();

            // Act
            OpenSSLECGroupContext reconstructed = OpenSSLECGroupContext.getInstance(spec);

            // Assert
            assertThat(reconstructed).isNotNull();
            assertThat(reconstructed.getCurveName()).isEqualTo(name);
        }
    }

    @Test
    public void getInstance_rawP224Parameters_recognizesSecp224r1()
            throws InvalidAlgorithmParameterException {
        // Arrange
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P224_P), P224_A, P224_B);
        ECPoint generator = new ECPoint(P224_X, P224_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P224_ORDER, P224_COFACTOR);

        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(spec);

        // Assert
        assertThat(group).isSameInstanceAs(OpenSSLECGroupContext.SECP224R1);
        assertThat(group.getCurveName()).isEqualTo("secp224r1");
    }

    @Test
    public void getInstance_rawP256Parameters_recognizesPrime256v1()
            throws InvalidAlgorithmParameterException {
        // Arrange
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P256_P), P256_A, P256_B);
        ECPoint generator = new ECPoint(P256_X, P256_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P256_ORDER, P256_COFACTOR);

        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(spec);

        // Assert
        assertThat(group).isSameInstanceAs(OpenSSLECGroupContext.PRIME256V1);
        assertThat(group.getCurveName()).isEqualTo("prime256v1");
    }

    @Test
    public void getInstance_rawP384Parameters_recognizesSecp384r1()
            throws InvalidAlgorithmParameterException {
        // Arrange
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P384_P), P384_A, P384_B);
        ECPoint generator = new ECPoint(P384_X, P384_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P384_ORDER, P384_COFACTOR);

        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(spec);

        // Assert
        assertThat(group).isSameInstanceAs(OpenSSLECGroupContext.SECP384R1);
        assertThat(group.getCurveName()).isEqualTo("secp384r1");
    }

    @Test
    public void getInstance_rawP521Parameters_recognizesSecp521r1()
            throws InvalidAlgorithmParameterException {
        // Arrange
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P521_P), P521_A, P521_B);
        ECPoint generator = new ECPoint(P521_X, P521_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P521_ORDER, P521_COFACTOR);

        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(spec);

        // Assert
        assertThat(group).isSameInstanceAs(OpenSSLECGroupContext.SECP521R1);
        assertThat(group.getCurveName()).isEqualTo("secp521r1");
    }

    // --- getInstance Field Type Tests ---

    @Test
    public void getInstance_binaryFieldF2m_throwsInvalidParameterException() {
        // Arrange
        EllipticCurve curve =
                new EllipticCurve(new ECFieldF2m(163), BigInteger.ONE, BigInteger.ONE);
        ECPoint generator = new ECPoint(BigInteger.ONE, BigInteger.ONE);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, BigInteger.ONE, 1);

        // Act & Assert
        InvalidParameterException e = assertThrows(InvalidParameterException.class,
                                                   () -> OpenSSLECGroupContext.getInstance(spec));
        assertThat(e).hasMessageThat().contains("unhandled field class");
        assertThat(e).hasMessageThat().contains("ECFieldF2m");
    }

    // --- getInstance Mismatched Bit Length Parameters (Fall through to Arbitrary) ---

    @Test
    public void getInstance_p256BitLengthWithMismatchedB_fallsThroughToArbitraryAndFails() {
        // Arrange: 256-bit prime, but 'b' altered so it does not match prime256v1
        EllipticCurve curve =
                new EllipticCurve(new ECFieldFp(P256_P), P256_A, P256_B.add(BigInteger.ONE));
        ECPoint generator = new ECPoint(P256_X, P256_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P256_ORDER, P256_COFACTOR);

        // Act & Assert: generator is not on modified curve -> arbitrary curve creation fails
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> OpenSSLECGroupContext.getInstance(spec));
    }

    // --- getInstance Arbitrary Curve Creation Tests ---

    @Test
    public void getInstance_validArbitraryCurveSecp192r1_succeeds()
            throws InvalidAlgorithmParameterException {
        // Arrange: 192-bit NIST curve is valid over ECFieldFp, but not in the 224/256/384/521
        // switch
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P192_P), P192_A, P192_B);
        ECPoint generator = new ECPoint(P192_X, P192_Y);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, P192_ORDER, P192_COFACTOR);

        // Act
        OpenSSLECGroupContext group = OpenSSLECGroupContext.getInstance(spec);

        // Assert
        assertThat(group).isNotNull();
        // Arbitrary curves do not have a registered curve name in BoringSSL EC_GROUP
        assertThat(group.getCurveName()).isNull();

        // Parameter spec round-trip
        ECParameterSpec reconstructedSpec = group.getECParameterSpec();
        assertThat(reconstructedSpec).isNotNull();
        assertThat(reconstructedSpec.getCofactor()).isEqualTo(P192_COFACTOR);
        assertThat(reconstructedSpec.getOrder()).isEqualTo(P192_ORDER);
        assertThat(((ECFieldFp) reconstructedSpec.getCurve().getField()).getP()).isEqualTo(P192_P);
        assertThat(reconstructedSpec.getCurve().getA()).isEqualTo(P192_A);
        assertThat(reconstructedSpec.getCurve().getB()).isEqualTo(P192_B);
        assertThat(reconstructedSpec.getGenerator().getAffineX()).isEqualTo(P192_X);
        assertThat(reconstructedSpec.getGenerator().getAffineY()).isEqualTo(P192_Y);

        // Can round-trip back into getInstance
        OpenSSLECGroupContext group2 = OpenSSLECGroupContext.getInstance(reconstructedSpec);
        assertThat(group2).isNotNull();
        assertThat(group2.getCurveName()).isNull();
    }

    @Test
    public void
    getInstance_arbitraryCurveWithInvalidGenerator_throwsInvalidAlgorithmParameterException() {
        // Arrange: generator point not on curve
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(P192_P), P192_A, P192_B);
        ECPoint invalidGenerator = new ECPoint(P192_X, P192_Y.add(BigInteger.ONE));
        ECParameterSpec spec =
                new ECParameterSpec(curve, invalidGenerator, P192_ORDER, P192_COFACTOR);

        // Act & Assert
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> OpenSSLECGroupContext.getInstance(spec));
    }

    @Test
    public void
    getInstance_arbitraryCurveWithInvalidPrime_throwsInvalidAlgorithmParameterException() {
        // Arrange: even prime is invalid for EC_GROUP_new_curve_GFp
        BigInteger evenP = new BigInteger("1000", 16);
        EllipticCurve curve =
                new EllipticCurve(new ECFieldFp(evenP), BigInteger.ONE, BigInteger.ONE);
        ECPoint generator = new ECPoint(BigInteger.ONE, BigInteger.ONE);
        ECParameterSpec spec = new ECParameterSpec(curve, generator, BigInteger.ONE, 1);

        // Act & Assert
        assertThrows(InvalidAlgorithmParameterException.class,
                     () -> OpenSSLECGroupContext.getInstance(spec));
    }

    @Test
    public void getInstance_nullParameterSpec_throwsNullPointerException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> OpenSSLECGroupContext.getInstance(null));
    }
}
