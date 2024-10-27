/*
 * Copyright (C) 2013 The Android Open Source Project
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

/**
 * An implementation of {@link X509CRL} based on BoringSSL.
 */
final class OpenSSLX509CRL extends X509CRL {
    private volatile long mContext;
    private final Date thisUpdate;
    private final Date nextUpdate;

    private OpenSSLX509CRL(long ctx) throws ParsingException {
        mContext = ctx;
        // The legacy X509 OpenSSL APIs don't validate ASN1_TIME structures until access, so
        // parse them here because this is the only time we're allowed to throw ParsingException
        thisUpdate = toDate(NativeCrypto.X509_CRL_get_lastUpdate(mContext, this));
        nextUpdate = toDate(NativeCrypto.X509_CRL_get_nextUpdate(mContext, this));
    }

    // Package-visible because it's also used by OpenSSLX509CRLEntry
    static Date toDate(long asn1time) throws ParsingException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.set(Calendar.MILLISECOND, 0);
        NativeCrypto.ASN1_TIME_to_Calendar(asn1time, calendar);
        return calendar.getTime();
    }

    static OpenSSLX509CRL fromX509DerInputStream(InputStream is) throws ParsingException {
        final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);

        try {
            final long crlCtx = NativeCrypto.d2i_X509_CRL_bio(bis.getBioContext());
            if (crlCtx == 0) {
                return null;
            }
            return new OpenSSLX509CRL(crlCtx);
        } catch (Exception e) {
            throw new ParsingException(e);
        } finally {
            bis.release();
        }
    }

    static List<OpenSSLX509CRL> fromPkcs7DerInputStream(InputStream is)
            throws ParsingException {
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);

        final long[] certRefs;
        try {
            certRefs = NativeCrypto.d2i_PKCS7_bio(bis.getBioContext(), NativeCrypto.PKCS7_CRLS);
        } catch (Exception e) {
            throw new ParsingException(e);
        } finally {
            bis.release();
        }

        final List<OpenSSLX509CRL> certs = new ArrayList<>(certRefs.length);
        for (long certRef : certRefs) {
            if (certRef == 0) {
                continue;
            }
            certs.add(new OpenSSLX509CRL(certRef));
        }
        return certs;
    }

    static OpenSSLX509CRL fromX509PemInputStream(InputStream is) throws ParsingException {
        final OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);

        try {
            final long crlCtx = NativeCrypto.PEM_read_bio_X509_CRL(bis.getBioContext());
            if (crlCtx == 0) {
                return null;
            }
            return new OpenSSLX509CRL(crlCtx);
        } catch (Exception e) {
            throw new ParsingException(e);
        } finally {
            bis.release();
        }
    }

    static List<OpenSSLX509CRL> fromPkcs7PemInputStream(InputStream is)
            throws ParsingException {
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(is, true);

        final long[] certRefs;
        try {
            certRefs = NativeCrypto.PEM_read_bio_PKCS7(bis.getBioContext(),
                    NativeCrypto.PKCS7_CRLS);
        } catch (Exception e) {
            throw new ParsingException(e);
        } finally {
            bis.release();
        }

        final List<OpenSSLX509CRL> certs = new ArrayList<>(certRefs.length);
        for (long certRef : certRefs) {
            if (certRef == 0) {
                continue;
            }
            certs.add(new OpenSSLX509CRL(certRef));
        }
        return certs;
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        String[] critOids =
                NativeCrypto.get_X509_CRL_ext_oids(mContext, this, NativeCrypto.EXTENSION_TYPE_CRITICAL);

        /*
         * This API has a special case that if there are no extensions, we
         * should return null. So if we have no critical extensions, we'll check
         * non-critical extensions.
         */
        if ((critOids.length == 0)
                && (NativeCrypto.get_X509_CRL_ext_oids(mContext, this,
                        NativeCrypto.EXTENSION_TYPE_NON_CRITICAL).length == 0)) {
            return null;
        }

        return new HashSet<>(Arrays.asList(critOids));
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return NativeCrypto.X509_CRL_get_ext_oid(mContext, this, oid);
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        String[] nonCritOids =
                NativeCrypto.get_X509_CRL_ext_oids(mContext, this,
                        NativeCrypto.EXTENSION_TYPE_NON_CRITICAL);

        /*
         * This API has a special case that if there are no extensions, we
         * should return null. So if we have no non-critical extensions, we'll
         * check critical extensions.
         */
        if ((nonCritOids.length == 0)
                && (NativeCrypto.get_X509_CRL_ext_oids(mContext, this,
                        NativeCrypto.EXTENSION_TYPE_CRITICAL).length == 0)) {
            return null;
        }

        return new HashSet<>(Arrays.asList(nonCritOids));
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        final String[] criticalOids =
                NativeCrypto.get_X509_CRL_ext_oids(mContext, this, NativeCrypto.EXTENSION_TYPE_CRITICAL);
        for (String oid : criticalOids) {
            final long extensionRef = NativeCrypto.X509_CRL_get_ext(mContext, this, oid);
            if (NativeCrypto.X509_supported_extension(extensionRef) != 1) {
                return true;
            }
        }

        return false;
    }

    @Override
    public byte[] getEncoded() throws CRLException {
        return NativeCrypto.i2d_X509_CRL(mContext, this);
    }

    private void verifyOpenSSL(OpenSSLKey pkey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        try {
            NativeCrypto.X509_CRL_verify(mContext, this, pkey.getNativeRef());
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new SignatureException(e);
        }
    }

    private void verifyInternal(PublicKey key, String sigProvider) throws NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        String sigAlg = getSigAlgName();
        if (sigAlg == null) {
            sigAlg = getSigAlgOID();
        }

        final Signature sig;
        if (sigProvider == null) {
            sig = Signature.getInstance(sigAlg);
        } else {
            sig = Signature.getInstance(sigAlg, sigProvider);
        }

        sig.initVerify(key);
        sig.update(getTBSCertList());
        if (!sig.verify(getSignature())) {
            throw new SignatureException("signature did not verify");
        }
    }

    @Override
    public void verify(PublicKey key) throws CRLException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        if (key instanceof OpenSSLKeyHolder) {
            OpenSSLKey pkey = ((OpenSSLKeyHolder) key).getOpenSSLKey();
            verifyOpenSSL(pkey);
            return;
        }

        verifyInternal(key, null);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CRLException,
            NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
            SignatureException {
        verifyInternal(key, sigProvider);
    }

    @Override
    public int getVersion() {
        return (int) NativeCrypto.X509_CRL_get_version(mContext, this) + 1;
    }

    @Override
    public Principal getIssuerDN() {
        return getIssuerX500Principal();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        final byte[] issuer = NativeCrypto.X509_CRL_get_issuer_name(mContext, this);
        return new X500Principal(issuer);
    }

    @Override
    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
    public Date getThisUpdate() {
        return (Date) thisUpdate.clone();
    }

    @Override
    @SuppressWarnings({"JavaUtilDate"}) // Needed for API compatibility
    public Date getNextUpdate() {
        return (Date) nextUpdate.clone();
    }

    @Override
    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        final long revokedRef = NativeCrypto.X509_CRL_get0_by_serial(mContext, this,
                serialNumber.toByteArray());
        if (revokedRef == 0) {
            return null;
        }
        try {
            return new OpenSSLX509CRLEntry(NativeCrypto.X509_REVOKED_dup(revokedRef));
        } catch (ParsingException e) {
            return null;
        }
    }

    @Override
    public X509CRLEntry getRevokedCertificate(X509Certificate certificate) {
        if (certificate instanceof OpenSSLX509Certificate) {
            OpenSSLX509Certificate osslCert = (OpenSSLX509Certificate) certificate;
            final long x509RevokedRef = NativeCrypto.X509_CRL_get0_by_cert(mContext, this,
                    osslCert.getContext(), osslCert);

            if (x509RevokedRef == 0) {
                return null;
            }

            try {
                return new OpenSSLX509CRLEntry(NativeCrypto.X509_REVOKED_dup(x509RevokedRef));
            } catch (ParsingException e) {
                return null;
            }
        }

        return getRevokedCertificate(certificate.getSerialNumber());
    }

    @Override
    public Set<? extends X509CRLEntry> getRevokedCertificates() {
        final long[] entryRefs = NativeCrypto.X509_CRL_get_REVOKED(mContext, this);
        if (entryRefs == null || entryRefs.length == 0) {
            return null;
        }

        final Set<OpenSSLX509CRLEntry> crlSet = new HashSet<>();
        for (long entryRef : entryRefs) {
            try {
                crlSet.add(new OpenSSLX509CRLEntry(entryRef));
            } catch (ParsingException e) {
                // Skip this entry
            }
        }

        return crlSet;
    }

    @Override
    public byte[] getTBSCertList() {
        return NativeCrypto.get_X509_CRL_crl_enc(mContext, this);
    }

    @Override
    public byte[] getSignature() {
        return NativeCrypto.get_X509_CRL_signature(mContext, this);
    }

    @Override
    public String getSigAlgName() {
        String oid = getSigAlgOID();
        String algName = OidData.oidToAlgorithmName(oid);
        if (algName != null) {
            return algName;
        }
        algName = Platform.oidToAlgorithmName(oid);
        if (algName != null) {
            return algName;
        }
        return oid;
    }

    @Override
    public String getSigAlgOID() {
        return NativeCrypto.get_X509_CRL_sig_alg_oid(mContext, this);
    }

    @Override
    public byte[] getSigAlgParams() {
        return NativeCrypto.get_X509_CRL_sig_alg_parameter(mContext, this);
    }

    @Override
    public boolean isRevoked(Certificate cert) {
        if (!(cert instanceof X509Certificate)) {
            return false;
        }

        final OpenSSLX509Certificate osslCert;
        if (cert instanceof OpenSSLX509Certificate) {
            osslCert = (OpenSSLX509Certificate) cert;
        } else {
            try {
                osslCert = OpenSSLX509Certificate.fromX509DerInputStream(new ByteArrayInputStream(
                        cert.getEncoded()));
            } catch (Exception e) {
                throw new RuntimeException("cannot convert certificate", e);
            }
        }

        final long x509RevokedRef = NativeCrypto.X509_CRL_get0_by_cert(mContext, this,
                osslCert.getContext(), osslCert);

        return x509RevokedRef != 0;
    }

    @Override
    public String toString() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        final long bioCtx = NativeCrypto.create_BIO_OutputStream(os);
        try {
            NativeCrypto.X509_CRL_print(bioCtx, mContext, this);
            return os.toString();
        } finally {
            NativeCrypto.BIO_free_all(bioCtx);
        }
    }

    @Override
    @SuppressWarnings("Finalize")
    protected void finalize() throws Throwable {
        try {
            long toFree = mContext;
            if (toFree != 0) {
                mContext = 0;
                NativeCrypto.X509_CRL_free(toFree, this);
            }
        } finally {
            super.finalize();
        }
    }

}
