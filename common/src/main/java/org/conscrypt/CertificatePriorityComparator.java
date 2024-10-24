/*
 * Copyright (C) 2016 The Android Open Source Project
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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link Comparator} for prioritizing certificates in path building.
 *
 * <p>
 * The sort order is as follows:
 * <ol>
 * <li>Self-issued certificates first.</li>
 * <li>Strength of certificates descending (EC before RSA, key size descending, signature
 * algorithm strength descending).</li>
 * <li>notAfter date descending.</li>
 * <li>notBefore date descending.</li>
 * </ol>
 * </p>
 */
@Internal
public final class CertificatePriorityComparator implements Comparator<X509Certificate> {

    /**
     * Map of signature algorithm OIDs to priorities. OIDs with a lower priority will be sorted
     * before those with higher.
     */
    private static final Map<String, Integer> ALGORITHM_OID_PRIORITY_MAP;

    /*
     * Priorities of digest algorithms. Lower is better.
     */
    private static final Integer PRIORITY_MD5 = 6;
    private static final Integer PRIORITY_SHA1 = 5;
    private static final Integer PRIORITY_SHA224 = 4;
    private static final Integer PRIORITY_SHA256 = 3;
    private static final Integer PRIORITY_SHA384 = 2;
    private static final Integer PRIORITY_SHA512 = 1;
    private static final Integer PRIORITY_UNKNOWN = -1;
    static {
        ALGORITHM_OID_PRIORITY_MAP = new HashMap<String, Integer>();
        // RSA oids
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.13", PRIORITY_SHA512);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.12", PRIORITY_SHA384);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.11", PRIORITY_SHA256);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.14", PRIORITY_SHA224);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.5", PRIORITY_SHA1);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.113549.1.1.4", PRIORITY_MD5);
        // ECDSA oids
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.10045.4.3.4", PRIORITY_SHA512);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.10045.4.3.3", PRIORITY_SHA384);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.10045.4.3.2", PRIORITY_SHA256);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.10045.4.3.1", PRIORITY_SHA224);
        ALGORITHM_OID_PRIORITY_MAP.put("1.2.840.10045.4.1", PRIORITY_SHA1);
    }

    @Override
    @SuppressWarnings({"JdkObsolete", "JavaUtilDate"})  // Certificate uses Date
    public int compare(X509Certificate lhs, X509Certificate rhs) {
        int result;
        boolean lhsSelfSigned = lhs.getSubjectDN().equals(lhs.getIssuerDN());
        boolean rhsSelfSigned = rhs.getSubjectDN().equals(rhs.getIssuerDN());
        // Self-issued before not self-issued to avoid trying bridge certs first.
        if (lhsSelfSigned != rhsSelfSigned) {
            return rhsSelfSigned ? 1 : -1;
        }
        // Strength descending.
        result = compareStrength(rhs, lhs);
        if (result != 0) {
            return result;
        }
        // notAfter descending.
        Date lhsNotAfter = lhs.getNotAfter();
        Date rhsNotAfter = rhs.getNotAfter();
        result = rhsNotAfter.compareTo(lhsNotAfter);
        if (result != 0) {
            return result;
        }
        // notBefore descending.
        Date lhsNotBefore = lhs.getNotBefore();
        Date rhsNotBefore = rhs.getNotBefore();
        return rhsNotBefore.compareTo(lhsNotBefore);
    }

    private int compareStrength(X509Certificate lhs, X509Certificate rhs) {
        int result;
        PublicKey lhsPublicKey = lhs.getPublicKey();
        PublicKey rhsPublicKey = rhs.getPublicKey();
        result = compareKeyAlgorithm(lhsPublicKey, rhsPublicKey);
        if (result != 0) {
            return result;
        }
        result = compareKeySize(lhsPublicKey, rhsPublicKey);
        if (result != 0) {
            return result;
        }
        return compareSignatureAlgorithm(lhs, rhs);
    }

    private int compareKeyAlgorithm(PublicKey lhs, PublicKey rhs) {
        String lhsAlgorithm = lhs.getAlgorithm();
        String rhsAlgorithm = rhs.getAlgorithm();

        if (lhsAlgorithm.equalsIgnoreCase(rhsAlgorithm)) {
            return 0;
        }

        // Prefer EC to RSA.
        if ("EC".equalsIgnoreCase(lhsAlgorithm)) {
            return 1;
        } else {
            return -1;
        }
    }

    private int compareKeySize(PublicKey lhs, PublicKey rhs) {
        String lhsAlgorithm = lhs.getAlgorithm();
        String rhsAlgorithm = rhs.getAlgorithm();
        if (!lhsAlgorithm.equalsIgnoreCase(rhsAlgorithm)) {
            throw new IllegalArgumentException("Keys are not of the same type");
        }
        int lhsSize = getKeySize(lhs);
        int rhsSize = getKeySize(rhs);
        return lhsSize - rhsSize;
    }

    private int getKeySize(PublicKey pkey) {
        if (pkey instanceof ECPublicKey) {
            return ((ECPublicKey) pkey).getParams().getCurve().getField().getFieldSize();
        } else if (pkey instanceof RSAPublicKey) {
            return ((RSAPublicKey) pkey).getModulus().bitLength();
        } else {
            throw new IllegalArgumentException(
                    "Unsupported public key type: " + pkey.getClass().getName());
        }
    }

    private int compareSignatureAlgorithm(X509Certificate lhs, X509Certificate rhs) {
        Integer lhsPriority = ALGORITHM_OID_PRIORITY_MAP.get(lhs.getSigAlgOID());
        Integer rhsPriority = ALGORITHM_OID_PRIORITY_MAP.get(rhs.getSigAlgOID());
        if (lhsPriority == null) {
            lhsPriority = PRIORITY_UNKNOWN;
        }
        if (rhsPriority == null) {
            rhsPriority = PRIORITY_UNKNOWN;
        }
        return rhsPriority - lhsPriority;
    }
}
