/*
 * Copyright (C) 2008 The Android Open Source Project
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

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.Buffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.SSLException;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.OpenSSLX509CertificateFactory.ParsingException;

/**
 * Provides the Java side of our JNI glue for OpenSSL.
 *
 * @hide
 */
@Internal
public final class NativeCrypto {
    // --- OpenSSL library initialization --------------------------------------
    private static final UnsatisfiedLinkError loadError;
    static {
        UnsatisfiedLinkError error = null;
        try {
            NativeCryptoJni.init();
            clinit();
        } catch (UnsatisfiedLinkError t) {
            // Don't rethrow the error, so that we can later on interrogate the
            // value of loadError.
            error = t;
        }
        loadError = error;
    }

    private native static void clinit();

    /**
     * Checks to see whether or not the native library was successfully loaded. If not, throws
     * the {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
     */
    static void checkAvailability() {
        if (loadError != null) {
            throw loadError;
        }
    }

    // --- DSA/RSA public/private key handling functions -----------------------

    static native long EVP_PKEY_new_RSA(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q,
            byte[] dmp1, byte[] dmq1, byte[] iqmp);

    static native int EVP_PKEY_type(NativeRef.EVP_PKEY pkey);

    static native String EVP_PKEY_print_public(NativeRef.EVP_PKEY pkeyRef);

    static native String EVP_PKEY_print_params(NativeRef.EVP_PKEY pkeyRef);

    static native void EVP_PKEY_free(long pkey);

    static native int EVP_PKEY_cmp(NativeRef.EVP_PKEY pkey1, NativeRef.EVP_PKEY pkey2);

    static native byte[] EVP_marshal_private_key(NativeRef.EVP_PKEY pkey);

    static native long EVP_parse_private_key(byte[] data) throws ParsingException;

    static native byte[] EVP_marshal_public_key(NativeRef.EVP_PKEY pkey);

    static native long EVP_parse_public_key(byte[] data) throws ParsingException;

    static native long PEM_read_bio_PUBKEY(long bioCtx);

    static native long PEM_read_bio_PrivateKey(long bioCtx);

    static native long getRSAPrivateKeyWrapper(PrivateKey key, byte[] modulus);

    static native long getECPrivateKeyWrapper(PrivateKey key, NativeRef.EC_GROUP ecGroupRef);

    static native long RSA_generate_key_ex(int modulusBits, byte[] publicExponent);

    static native int RSA_size(NativeRef.EVP_PKEY pkey);

    static native int RSA_private_encrypt(
            int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);

    static native int RSA_public_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
            int padding) throws BadPaddingException, SignatureException;

    static native int RSA_public_encrypt(
            int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey, int padding);

    static native int RSA_private_decrypt(int flen, byte[] from, byte[] to, NativeRef.EVP_PKEY pkey,
            int padding) throws BadPaddingException, SignatureException;

    /**
     * @return array of {n, e}
     */
    static native byte[][] get_RSA_public_params(NativeRef.EVP_PKEY rsa);

    /**
     * @return array of {n, e, d, p, q, dmp1, dmq1, iqmp}
     */
    static native byte[][] get_RSA_private_params(NativeRef.EVP_PKEY rsa);

    // --- EC functions --------------------------

    static native long EVP_PKEY_new_EC_KEY(
            NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pubkeyRef, byte[] privkey);

    static native long EC_GROUP_new_by_curve_name(String curveName);

    static native long EC_GROUP_new_arbitrary(
            byte[] p, byte[] a, byte[] b, byte[] x, byte[] y, byte[] order, int cofactor);

    static native String EC_GROUP_get_curve_name(NativeRef.EC_GROUP groupRef);

    static native byte[][] EC_GROUP_get_curve(NativeRef.EC_GROUP groupRef);

    static native void EC_GROUP_clear_free(long groupRef);

    static native long EC_GROUP_get_generator(NativeRef.EC_GROUP groupRef);

    static native byte[] EC_GROUP_get_order(NativeRef.EC_GROUP groupRef);

    static native int EC_GROUP_get_degree(NativeRef.EC_GROUP groupRef);

    static native byte[] EC_GROUP_get_cofactor(NativeRef.EC_GROUP groupRef);

    static native long EC_POINT_new(NativeRef.EC_GROUP groupRef);

    static native void EC_POINT_clear_free(long pointRef);

    static native byte[][] EC_POINT_get_affine_coordinates(
            NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef);

    static native void EC_POINT_set_affine_coordinates(
            NativeRef.EC_GROUP groupRef, NativeRef.EC_POINT pointRef, byte[] x, byte[] y);

    static native long EC_KEY_generate_key(NativeRef.EC_GROUP groupRef);

    static native long EC_KEY_get1_group(NativeRef.EVP_PKEY pkeyRef);

    static native byte[] EC_KEY_get_private_key(NativeRef.EVP_PKEY keyRef);

    static native long EC_KEY_get_public_key(NativeRef.EVP_PKEY keyRef);

    static native byte[] EC_KEY_marshal_curve_name(NativeRef.EC_GROUP groupRef) throws IOException;

    static native long EC_KEY_parse_curve_name(byte[] encoded) throws IOException;

    static native int ECDH_compute_key(byte[] out, int outOffset, NativeRef.EVP_PKEY publicKeyRef,
            NativeRef.EVP_PKEY privateKeyRef) throws InvalidKeyException, IndexOutOfBoundsException;

    static native int ECDSA_size(NativeRef.EVP_PKEY pkey);

    static native int ECDSA_sign(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);

    static native int ECDSA_verify(byte[] data, byte[] sig, NativeRef.EVP_PKEY pkey);

    // --- Message digest functions --------------

    // These return const references
    static native long EVP_get_digestbyname(String name);

    static native int EVP_MD_size(long evp_md_const);

    // --- Message digest context functions --------------

    static native long EVP_MD_CTX_create();

    static native void EVP_MD_CTX_cleanup(NativeRef.EVP_MD_CTX ctx);

    static native void EVP_MD_CTX_destroy(long ctx);

    static native int EVP_MD_CTX_copy_ex(
            NativeRef.EVP_MD_CTX dst_ctx, NativeRef.EVP_MD_CTX src_ctx);

    // --- Digest handling functions -------------------------------------------

    static native int EVP_DigestInit_ex(NativeRef.EVP_MD_CTX ctx, long evp_md);

    static native void EVP_DigestUpdate(
            NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);

    static native void EVP_DigestUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);

    static native int EVP_DigestFinal_ex(NativeRef.EVP_MD_CTX ctx, byte[] hash, int offset);

    // --- Signature handling functions ----------------------------------------

    static native long EVP_DigestSignInit(
            NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);

    static native long EVP_DigestVerifyInit(
            NativeRef.EVP_MD_CTX ctx, long evpMdRef, NativeRef.EVP_PKEY key);

    static native void EVP_DigestSignUpdate(
            NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);

    static native void EVP_DigestSignUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);

    static native void EVP_DigestVerifyUpdate(
            NativeRef.EVP_MD_CTX ctx, byte[] buffer, int offset, int length);

    static native void EVP_DigestVerifyUpdateDirect(NativeRef.EVP_MD_CTX ctx, long ptr, int length);

    static native byte[] EVP_DigestSignFinal(NativeRef.EVP_MD_CTX ctx);

    static native boolean EVP_DigestVerifyFinal(NativeRef.EVP_MD_CTX ctx, byte[] signature,
            int offset, int length) throws IndexOutOfBoundsException;

    static native long EVP_PKEY_encrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;

    static native int EVP_PKEY_encrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
            byte[] input, int inOffset, int inLength)
            throws IndexOutOfBoundsException, BadPaddingException;

    static native long EVP_PKEY_decrypt_init(NativeRef.EVP_PKEY pkey) throws InvalidKeyException;

    static native int EVP_PKEY_decrypt(NativeRef.EVP_PKEY_CTX ctx, byte[] out, int outOffset,
            byte[] input, int inOffset, int inLength)
            throws IndexOutOfBoundsException, BadPaddingException;

    static native void EVP_PKEY_CTX_free(long pkeyCtx);

    static native void EVP_PKEY_CTX_set_rsa_padding(long ctx, int pad)
            throws InvalidAlgorithmParameterException;

    static native void EVP_PKEY_CTX_set_rsa_pss_saltlen(long ctx, int len)
            throws InvalidAlgorithmParameterException;

    static native void EVP_PKEY_CTX_set_rsa_mgf1_md(long ctx, long evpMdRef)
            throws InvalidAlgorithmParameterException;

    static native void EVP_PKEY_CTX_set_rsa_oaep_md(long ctx, long evpMdRef)
            throws InvalidAlgorithmParameterException;

    static native void EVP_PKEY_CTX_set_rsa_oaep_label(long ctx, byte[] label)
            throws InvalidAlgorithmParameterException;

    // --- Block ciphers -------------------------------------------------------

    // These return const references
    static native long EVP_get_cipherbyname(String string);

    static native void EVP_CipherInit_ex(NativeRef.EVP_CIPHER_CTX ctx, long evpCipher, byte[] key,
            byte[] iv, boolean encrypting);

    static native int EVP_CipherUpdate(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset,
            byte[] in, int inOffset, int inLength) throws IndexOutOfBoundsException;

    static native int EVP_CipherFinal_ex(NativeRef.EVP_CIPHER_CTX ctx, byte[] out, int outOffset)
            throws BadPaddingException, IllegalBlockSizeException;

    static native int EVP_CIPHER_iv_length(long evpCipher);

    static native long EVP_CIPHER_CTX_new();

    static native int EVP_CIPHER_CTX_block_size(NativeRef.EVP_CIPHER_CTX ctx);

    static native int get_EVP_CIPHER_CTX_buf_len(NativeRef.EVP_CIPHER_CTX ctx);

    static native boolean get_EVP_CIPHER_CTX_final_used(NativeRef.EVP_CIPHER_CTX ctx);

    static native void EVP_CIPHER_CTX_set_padding(
            NativeRef.EVP_CIPHER_CTX ctx, boolean enablePadding);

    static native void EVP_CIPHER_CTX_set_key_length(NativeRef.EVP_CIPHER_CTX ctx, int keyBitSize);

    static native void EVP_CIPHER_CTX_free(long ctx);

    // --- AEAD ----------------------------------------------------------------
    static native long EVP_aead_aes_128_gcm();

    static native long EVP_aead_aes_256_gcm();

    static native int EVP_AEAD_max_overhead(long evpAead);

    static native int EVP_AEAD_nonce_length(long evpAead);

    static native int EVP_AEAD_CTX_seal(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
            int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
            throws BadPaddingException, IndexOutOfBoundsException;

    static native int EVP_AEAD_CTX_open(long evpAead, byte[] key, int tagLengthInBytes, byte[] out,
            int outOffset, byte[] nonce, byte[] in, int inOffset, int inLength, byte[] ad)
            throws BadPaddingException, IndexOutOfBoundsException;

    // --- HMAC functions ------------------------------------------------------

    static native long HMAC_CTX_new();

    static native void HMAC_CTX_free(long ctx);

    static native void HMAC_Init_ex(NativeRef.HMAC_CTX ctx, byte[] key, long evp_md);

    static native void HMAC_Update(NativeRef.HMAC_CTX ctx, byte[] in, int inOffset, int inLength);

    static native void HMAC_UpdateDirect(NativeRef.HMAC_CTX ctx, long inPtr, int inLength);

    static native byte[] HMAC_Final(NativeRef.HMAC_CTX ctx);

    // --- RAND ----------------------------------------------------------------

    static native void RAND_bytes(byte[] output);

    // --- X509_NAME -----------------------------------------------------------

    static int X509_NAME_hash(X500Principal principal) {
        return X509_NAME_hash(principal, "SHA1");
    }

    public static int X509_NAME_hash_old(X500Principal principal) {
        return X509_NAME_hash(principal, "MD5");
    }
    private static int X509_NAME_hash(X500Principal principal, String algorithm) {
        try {
            byte[] digest = MessageDigest.getInstance(algorithm).digest(principal.getEncoded());
            int offset = 0;
            return (((digest[offset++] & 0xff) << 0) | ((digest[offset++] & 0xff) << 8)
                    | ((digest[offset++] & 0xff) << 16) | ((digest[offset] & 0xff) << 24));
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    // --- X509 ----------------------------------------------------------------

    /** Used to request get_X509_GENERAL_NAME_stack get the "altname" field. */
    static final int GN_STACK_SUBJECT_ALT_NAME = 1;

    /**
     * Used to request get_X509_GENERAL_NAME_stack get the issuerAlternativeName
     * extension.
     */
    static final int GN_STACK_ISSUER_ALT_NAME = 2;

    /**
     * Used to request only non-critical types in get_X509*_ext_oids.
     */
    static final int EXTENSION_TYPE_NON_CRITICAL = 0;

    /**
     * Used to request only critical types in get_X509*_ext_oids.
     */
    static final int EXTENSION_TYPE_CRITICAL = 1;

    static native long d2i_X509_bio(long bioCtx);

    static native long d2i_X509(byte[] encoded) throws ParsingException;

    static native long PEM_read_bio_X509(long bioCtx);

    static native byte[] i2d_X509(long x509ctx);

    /** Takes an X509 context not an X509_PUBKEY context. */
    static native byte[] i2d_X509_PUBKEY(long x509ctx);

    static native byte[] ASN1_seq_pack_X509(long[] x509CertRefs);

    static native long[] ASN1_seq_unpack_X509_bio(long bioRef) throws ParsingException;

    static native void X509_free(long x509ctx);

    static native long X509_dup(long x509ctx);

    static native int X509_cmp(long x509ctx1, long x509ctx2);

    static native void X509_print_ex(long bioCtx, long x509ctx, long nmflag, long certflag);

    static native byte[] X509_get_issuer_name(long x509ctx);

    static native byte[] X509_get_subject_name(long x509ctx);

    static native String get_X509_sig_alg_oid(long x509ctx);

    static native byte[] get_X509_sig_alg_parameter(long x509ctx);

    static native boolean[] get_X509_issuerUID(long x509ctx);

    static native boolean[] get_X509_subjectUID(long x509ctx);

    static native long X509_get_pubkey(long x509ctx)
            throws NoSuchAlgorithmException, InvalidKeyException;

    static native String get_X509_pubkey_oid(long x509ctx);

    static native byte[] X509_get_ext_oid(long x509ctx, String oid);

    static native String[] get_X509_ext_oids(long x509ctx, int critical);

    static native Object[][] get_X509_GENERAL_NAME_stack(long x509ctx, int type)
            throws CertificateParsingException;

    static native boolean[] get_X509_ex_kusage(long x509ctx);

    static native String[] get_X509_ex_xkusage(long x509ctx);

    static native int get_X509_ex_pathlen(long x509ctx);

    static native long X509_get_notBefore(long x509ctx);

    static native long X509_get_notAfter(long x509ctx);

    static native long X509_get_version(long x509ctx);

    static native byte[] X509_get_serialNumber(long x509ctx);

    static native void X509_verify(long x509ctx, NativeRef.EVP_PKEY pkeyCtx)
            throws BadPaddingException;

    static native byte[] get_X509_cert_info_enc(long x509ctx);

    static native byte[] get_X509_signature(long x509ctx);

    static native int get_X509_ex_flags(long x509ctx);

    // Used by Android platform TrustedCertificateStore.
    @SuppressWarnings("unused")
    static native int X509_check_issued(long ctx, long ctx2);

    // --- PKCS7 ---------------------------------------------------------------

    /** Used as the "which" field in d2i_PKCS7_bio and PEM_read_bio_PKCS7. */
    static final int PKCS7_CERTS = 1;

    /** Used as the "which" field in d2i_PKCS7_bio and PEM_read_bio_PKCS7. */
    static final int PKCS7_CRLS = 2;

    /** Returns an array of X509 or X509_CRL pointers. */
    static native long[] d2i_PKCS7_bio(long bioCtx, int which) throws ParsingException;

    /** Returns an array of X509 or X509_CRL pointers. */
    static native byte[] i2d_PKCS7(long[] certs);

    /** Returns an array of X509 or X509_CRL pointers. */
    static native long[] PEM_read_bio_PKCS7(long bioCtx, int which);

    // --- X509_CRL ------------------------------------------------------------

    static native long d2i_X509_CRL_bio(long bioCtx);

    static native long PEM_read_bio_X509_CRL(long bioCtx);

    static native byte[] i2d_X509_CRL(long x509CrlCtx);

    static native void X509_CRL_free(long x509CrlCtx);

    static native void X509_CRL_print(long bioCtx, long x509CrlCtx);

    static native String get_X509_CRL_sig_alg_oid(long x509CrlCtx);

    static native byte[] get_X509_CRL_sig_alg_parameter(long x509CrlCtx);

    static native byte[] X509_CRL_get_issuer_name(long x509CrlCtx);

    /** Returns X509_REVOKED reference that is not duplicated! */
    static native long X509_CRL_get0_by_cert(long x509CrlCtx, long x509Ctx);

    /** Returns X509_REVOKED reference that is not duplicated! */
    static native long X509_CRL_get0_by_serial(long x509CrlCtx, byte[] serial);

    /** Returns an array of X509_REVOKED that are owned by the caller. */
    static native long[] X509_CRL_get_REVOKED(long x509CrlCtx);

    static native String[] get_X509_CRL_ext_oids(long x509ctx, int critical);

    static native byte[] X509_CRL_get_ext_oid(long x509CrlCtx, String oid);

    static native void X509_delete_ext(long x509, String oid);

    static native long X509_CRL_get_version(long x509CrlCtx);

    static native long X509_CRL_get_ext(long x509CrlCtx, String oid);

    static native byte[] get_X509_CRL_signature(long x509ctx);

    static native void X509_CRL_verify(long x509CrlCtx, NativeRef.EVP_PKEY pkeyCtx);

    static native byte[] get_X509_CRL_crl_enc(long x509CrlCtx);

    static native long X509_CRL_get_lastUpdate(long x509CrlCtx);

    static native long X509_CRL_get_nextUpdate(long x509CrlCtx);

    // --- X509_REVOKED --------------------------------------------------------

    static native long X509_REVOKED_dup(long x509RevokedCtx);

    static native byte[] i2d_X509_REVOKED(long x509RevokedCtx);

    static native String[] get_X509_REVOKED_ext_oids(long x509ctx, int critical);

    static native byte[] X509_REVOKED_get_ext_oid(long x509RevokedCtx, String oid);

    static native byte[] X509_REVOKED_get_serialNumber(long x509RevokedCtx);

    static native long X509_REVOKED_get_ext(long x509RevokedCtx, String oid);

    /** Returns ASN1_TIME reference. */
    static native long get_X509_REVOKED_revocationDate(long x509RevokedCtx);

    static native void X509_REVOKED_print(long bioRef, long x509RevokedCtx);

    // --- X509_EXTENSION ------------------------------------------------------

    static native int X509_supported_extension(long x509ExtensionRef);

    // --- ASN1_TIME -----------------------------------------------------------

    static native void ASN1_TIME_to_Calendar(long asn1TimeCtx, Calendar cal);

    // --- ASN1 Encoding -------------------------------------------------------

    /**
     * Allocates and returns an opaque reference to an object that can be used with other
     * asn1_read_* functions to read the ASN.1-encoded data in val.  The returned object must
     * be freed after use by calling asn1_read_free.
     */
    static native long asn1_read_init(byte[] val) throws IOException;

    /**
     * Allocates and returns an opaque reference to an object that can be used with other
     * asn1_read_* functions to read the ASN.1 sequence pointed to by cbsRef.  The returned
     * object must be freed after use by calling asn1_read_free.
     */
    static native long asn1_read_sequence(long cbsRef) throws IOException;

    /**
     * Returns whether the next object in the given reference is explicitly tagged with the
     * given tag number.
     */
    static native boolean asn1_read_next_tag_is(long cbsRef, int tag) throws IOException;

    /**
     * Allocates and returns an opaque reference to an object that can be used with
     * other asn1_read_* functions to read the ASN.1 data pointed to by cbsRef.  The returned
     * object must be freed after use by calling asn1_read_free.
     */
    static native long asn1_read_tagged(long cbsRef) throws IOException;

    /**
     * Returns the contents of an ASN.1 octet string from the given reference.
     */
    static native byte[] asn1_read_octetstring(long cbsRef) throws IOException;

    /**
     * Returns an ASN.1 integer from the given reference.  If the integer doesn't fit
     * in a uint64, this method will throw an IOException.
     */
    static native long asn1_read_uint64(long cbsRef) throws IOException;

    /**
     * Consumes an ASN.1 NULL from the given reference.
     */
    static native void asn1_read_null(long cbsRef) throws IOException;

    /**
     * Returns an ASN.1 OID in dotted-decimal notation (eg, "1.3.14.3.2.26" for SHA-1) from the
     * given reference.
     */
    static native String asn1_read_oid(long cbsRef) throws IOException;

    /**
     * Returns whether or not the given reference has been read completely.
     */
    static native boolean asn1_read_is_empty(long cbsRef);

    /**
     * Frees any resources associated with the given reference.  After calling, the reference
     * must not be used again.  This may be called with a zero reference, in which case nothing
     * will be done.
     */
    static native void asn1_read_free(long cbsRef);

    /**
     * Allocates and returns an opaque reference to an object that can be used with other
     * asn1_write_* functions to write ASN.1-encoded data.  The returned object must be finalized
     * after use by calling either asn1_write_finish or asn1_write_cleanup, and its resources
     * must be freed by calling asn1_write_free.
     */
    static native long asn1_write_init() throws IOException;

    /**
     * Allocates and returns an opaque reference to an object that can be used with other
     * asn1_write_* functions to write an ASN.1 sequence into the given reference.  The returned
     * reference may only be used until the next call on the parent reference.  The returned
     * object must be freed after use by calling asn1_write_free.
     */
    static native long asn1_write_sequence(long cbbRef) throws IOException;

    /**
     * Allocates and returns an opaque reference to an object that can be used with other
     * asn1_write_* functions to write a explicitly-tagged ASN.1 object with the given tag
     * into the given reference. The returned reference may only be used until the next
     * call on the parent reference.  The returned object must be freed after use by
     * calling asn1_write_free.
     */
    static native long asn1_write_tag(long cbbRef, int tag) throws IOException;

    /**
     * Writes the given data into the given reference as an ASN.1-encoded octet string.
     */
    static native void asn1_write_octetstring(long cbbRef, byte[] data) throws IOException;

    /**
     * Writes the given value into the given reference as an ASN.1-encoded integer.
     */
    static native void asn1_write_uint64(long cbbRef, long value) throws IOException;

    /**
     * Writes a NULL value into the given reference.
     */
    static native void asn1_write_null(long cbbRef) throws IOException;

    /**
     * Writes the given OID (which must be in dotted-decimal notation) into the given reference.
     */
    static native void asn1_write_oid(long cbbRef, String oid) throws IOException;

    /**
     * Flushes the given reference, invalidating any child references and completing their
     * operations.  This must be called if the child references are to be freed before
     * asn1_write_finish is called on the ultimate parent.  The child references must still
     * be freed.
     */
    static native void asn1_write_flush(long cbbRef) throws IOException;

    /**
     * Completes any in-progress operations and returns the ASN.1-encoded data.  Either this
     * or asn1_write_cleanup must be called on any reference returned from asn1_write_init
     * before it is freed.
     */
    static native byte[] asn1_write_finish(long cbbRef) throws IOException;

    /**
     * Cleans up intermediate state in the given reference.  Either this or asn1_write_finish
     * must be called on any reference returned from asn1_write_init before it is freed.
     */
    static native void asn1_write_cleanup(long cbbRef);

    /**
     * Frees resources associated with the given reference.  After calling, the reference
     * must not be used again.  This may be called with a zero reference, in which case nothing
     * will be done.
     */
    static native void asn1_write_free(long cbbRef);

    // --- BIO stream creation -------------------------------------------------

    static native long create_BIO_InputStream(OpenSSLBIOInputStream is, boolean isFinite);

    static native long create_BIO_OutputStream(OutputStream os);

    static native void BIO_free_all(long bioRef);

    // --- SSL handling --------------------------------------------------------

    static final String OBSOLETE_PROTOCOL_SSLV3 = "SSLv3";
    private static final String SUPPORTED_PROTOCOL_TLSV1 = "TLSv1";
    private static final String SUPPORTED_PROTOCOL_TLSV1_1 = "TLSv1.1";
    private static final String SUPPORTED_PROTOCOL_TLSV1_2 = "TLSv1.2";

    // SUPPORTED_CIPHER_SUITES_SET contains all the supported cipher suites, using their Java names.
    static final Set<String> SUPPORTED_CIPHER_SUITES_SET = new HashSet<String>();

    // SUPPORTED_LEGACY_CIPHER_SUITES_SET contains all the supported cipher suites using the legacy
    // OpenSSL-style names.
    private static final Set<String> SUPPORTED_LEGACY_CIPHER_SUITES_SET = new HashSet<String>();

    /**
     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV is RFC 5746's renegotiation
     * indication signaling cipher suite value. It is not a real
     * cipher suite. It is just an indication in the default and
     * supported cipher suite lists indicates that the implementation
     * supports secure renegotiation.
     * <p>
     * In the RI, its presence means that the SCSV is sent in the
     * cipher suite list to indicate secure renegotiation support and
     * its absense means to send an empty TLS renegotiation info
     * extension instead.
     * <p>
     * However, OpenSSL doesn't provide an API to give this level of
     * control, instead always sending the SCSV and always including
     * the empty renegotiation info if TLS is used (as opposed to
     * SSL). So we simply allow TLS_EMPTY_RENEGOTIATION_INFO_SCSV to
     * be passed for compatibility as to provide the hint that we
     * support secure renegotiation.
     */
    static final String TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";

    static String cipherSuiteToJava(String cipherSuite) {
        // For historical reasons, Java uses a different name for TLS_RSA_WITH_3DES_EDE_CBC_SHA.
        if ("TLS_RSA_WITH_3DES_EDE_CBC_SHA".equals(cipherSuite)) {
            return "SSL_RSA_WITH_3DES_EDE_CBC_SHA";
        }
        return cipherSuite;
    }

    static String cipherSuiteFromJava(String javaCipherSuite) {
        if ("SSL_RSA_WITH_3DES_EDE_CBC_SHA".equals(javaCipherSuite)) {
            return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        }
        return javaCipherSuite;
    }

    /**
     * TLS_FALLBACK_SCSV is from
     * https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00
     * to indicate to the server that this is a fallback protocol
     * request.
     */
    private static final String TLS_FALLBACK_SCSV = "TLS_FALLBACK_SCSV";

    private static final String[] SUPPORTED_CIPHER_SUITES;
    static {
        String[] allCipherSuites = get_cipher_names("ALL:!DHE");

        // get_cipher_names returns an array where even indices are the standard name and odd
        // indices are the OpenSSL name.
        int size = allCipherSuites.length;
        if (size % 2 != 0) {
            throw new IllegalArgumentException("Invalid cipher list returned by get_cipher_names");
        }
        SUPPORTED_CIPHER_SUITES = new String[size / 2 + 2];
        for (int i = 0; i < size; i += 2) {
            String cipherSuite = cipherSuiteToJava(allCipherSuites[i]);
            SUPPORTED_CIPHER_SUITES[i / 2] = cipherSuite;
            SUPPORTED_CIPHER_SUITES_SET.add(cipherSuite);

            SUPPORTED_LEGACY_CIPHER_SUITES_SET.add(allCipherSuites[i + 1]);
        }
        SUPPORTED_CIPHER_SUITES[size / 2] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
        SUPPORTED_CIPHER_SUITES[size / 2 + 1] = TLS_FALLBACK_SCSV;
    }

    /**
     * Returns 1 if the BoringSSL believes the CPU has AES accelerated hardware
     * instructions. Used to determine cipher suite ordering.
     */
    static native int EVP_has_aes_hardware();

    static native long SSL_CTX_new();

    // IMPLEMENTATION NOTE: The default list of cipher suites is a trade-off between what we'd like
    // to use and what servers currently support. We strive to be secure enough by default. We thus
    // avoid unacceptably weak suites (e.g., those with bulk cipher secret key shorter than 128
    // bits), while maintaining the capability to connect to the majority of servers.
    //
    // Cipher suites are listed in preference order (favorite choice first) of the client. However,
    // servers are not required to honor the order. The key rules governing the preference order
    // are:
    // * Prefer Forward Secrecy (i.e., cipher suites that use ECDHE and DHE for key agreement).
    // * Prefer ChaCha20-Poly1305 to AES-GCM unless hardware support for AES is available.
    // * Prefer AES-GCM to AES-CBC whose MAC-pad-then-encrypt approach leads to weaknesses (e.g.,
    //   Lucky 13).
    // * Prefer 128-bit bulk encryption to 256-bit one, because 128-bit is safe enough while
    //   consuming less CPU/time/energy.
    //
    // NOTE: Removing cipher suites from this list needs to be done with caution, because this may
    // prevent apps from connecting to servers they were previously able to connect to.

    /** X.509 based cipher suites enabled by default (if requested), in preference order. */
    private static final boolean HAS_AES_HARDWARE = EVP_has_aes_hardware() == 1;
    static final String[] DEFAULT_X509_CIPHER_SUITES = HAS_AES_HARDWARE ?
            new String[] {
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_AES_256_CBC_SHA",
            } :
            new String[] {
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_AES_256_CBC_SHA",
            };

    /** TLS-PSK cipher suites enabled by default (if requested), in preference order. */
    static final String[] DEFAULT_PSK_CIPHER_SUITES = new String[] {
            "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            "TLS_PSK_WITH_AES_128_CBC_SHA",
            "TLS_PSK_WITH_AES_256_CBC_SHA",
    };

    static String[] getSupportedCipherSuites() {
        return SUPPORTED_CIPHER_SUITES.clone();
    }

    static native void SSL_CTX_free(long ssl_ctx);

    static native void SSL_CTX_set_session_id_context(long ssl_ctx, byte[] sid_ctx);

    static native long SSL_CTX_set_timeout(long ssl_ctx, long seconds);

    static native long SSL_new(long ssl_ctx) throws SSLException;

    static native void SSL_enable_tls_channel_id(long ssl) throws SSLException;

    static native byte[] SSL_get_tls_channel_id(long ssl) throws SSLException;

    static native void SSL_set1_tls_channel_id(long ssl, NativeRef.EVP_PKEY pkey);

    /**
     * Sets the local certificates and private key.
     *
     * @param ssl the SSL reference.
     * @param encodedCertificates the encoded form of the local certificate chain.
     * @param pkey a reference to the private key.
     * @throws SSLException if a problem occurs setting the cert/key.
     */
    static native void setLocalCertsAndPrivateKey(long ssl, byte[][] encodedCertificates,
        NativeRef.EVP_PKEY pkey) throws SSLException;

    static native void SSL_set_client_CA_list(long ssl, byte[][] asn1DerEncodedX500Principals)
            throws SSLException;

    static native long SSL_set_mode(long ssl, long mode);

    static native long SSL_set_options(long ssl, long options);

    static native long SSL_clear_options(long ssl, long options);

    static native void SSL_enable_signed_cert_timestamps(long ssl);

    static native byte[] SSL_get_signed_cert_timestamp_list(long ssl);

    static native void SSL_set_signed_cert_timestamp_list(long ssl, byte[] list);

    static native void SSL_enable_ocsp_stapling(long ssl);

    static native byte[] SSL_get_ocsp_response(long ssl);

    static native void SSL_set_ocsp_response(long ssl, byte[] response);

    static native void SSL_use_psk_identity_hint(long ssl, String identityHint) throws SSLException;

    static native void set_SSL_psk_client_callback_enabled(long ssl, boolean enabled);

    static native void set_SSL_psk_server_callback_enabled(long ssl, boolean enabled);

    /** Protocols to enable by default when "TLSv1.2" is requested. */
    static final String[] TLSV12_PROTOCOLS = new String[] {
            SUPPORTED_PROTOCOL_TLSV1,
            SUPPORTED_PROTOCOL_TLSV1_1,
            SUPPORTED_PROTOCOL_TLSV1_2,
    };

    /** Protocols to enable by default when "TLSv1.1" is requested. */
    static final String[] TLSV11_PROTOCOLS = new String[] {
            SUPPORTED_PROTOCOL_TLSV1,
            SUPPORTED_PROTOCOL_TLSV1_1,
            SUPPORTED_PROTOCOL_TLSV1_2,
    };

    /** Protocols to enable by default when "TLSv1" is requested. */
    static final String[] TLSV1_PROTOCOLS = new String[] {
            SUPPORTED_PROTOCOL_TLSV1,
            SUPPORTED_PROTOCOL_TLSV1_1,
            SUPPORTED_PROTOCOL_TLSV1_2,
    };

    static final String[] DEFAULT_PROTOCOLS = TLSV12_PROTOCOLS;

    static String[] getSupportedProtocols() {
        return TLSV12_PROTOCOLS.clone();
    }

    static void setEnabledProtocols(long ssl, String[] protocols) {
        checkEnabledProtocols(protocols);
        // openssl uses negative logic letting you disable protocols.
        // so first, assume we need to set all (disable all) and clear none (enable none).
        // in the loop, selectively move bits from set to clear (from disable to enable)
        long optionsToSet = (NativeConstants.SSL_OP_NO_SSLv3 | NativeConstants.SSL_OP_NO_TLSv1
                | NativeConstants.SSL_OP_NO_TLSv1_1 | NativeConstants.SSL_OP_NO_TLSv1_2);
        long optionsToClear = 0;
        for (String protocol : protocols) {
            if (protocol.equals(SUPPORTED_PROTOCOL_TLSV1)) {
                optionsToSet &= ~NativeConstants.SSL_OP_NO_TLSv1;
                optionsToClear |= NativeConstants.SSL_OP_NO_TLSv1;
            } else if (protocol.equals(SUPPORTED_PROTOCOL_TLSV1_1)) {
                optionsToSet &= ~NativeConstants.SSL_OP_NO_TLSv1_1;
                optionsToClear |= NativeConstants.SSL_OP_NO_TLSv1_1;
            } else if (protocol.equals(SUPPORTED_PROTOCOL_TLSV1_2)) {
                optionsToSet &= ~NativeConstants.SSL_OP_NO_TLSv1_2;
                optionsToClear |= NativeConstants.SSL_OP_NO_TLSv1_2;
            } else if (protocol.equals(OBSOLETE_PROTOCOL_SSLV3)) {
                // Do nothing since we no longer support this protocol, but
                // allow it in the list of protocols so we can give an error
                // message about it if the handshake fails.
            } else {
                // error checked by checkEnabledProtocols
                throw new IllegalStateException();
            }
        }

        SSL_set_options(ssl, optionsToSet);
        SSL_clear_options(ssl, optionsToClear);
    }

    static String[] checkEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols == null");
        }
        for (String protocol : protocols) {
            if (protocol == null) {
                throw new IllegalArgumentException("protocols contains null");
            }
            if (!protocol.equals(SUPPORTED_PROTOCOL_TLSV1)
                    && !protocol.equals(SUPPORTED_PROTOCOL_TLSV1_1)
                    && !protocol.equals(SUPPORTED_PROTOCOL_TLSV1_2)
                    && !protocol.equals(OBSOLETE_PROTOCOL_SSLV3)) {
                throw new IllegalArgumentException("protocol " + protocol + " is not supported");
            }
        }
        return protocols;
    }

    static native void SSL_set_cipher_lists(long ssl, String[] ciphers);

    /**
     * Gets the list of cipher suites enabled for the provided {@code SSL} instance.
     *
     * @return array of {@code SSL_CIPHER} references.
     */
    static native long[] SSL_get_ciphers(long ssl);

    static void setEnabledCipherSuites(long ssl, String[] cipherSuites) {
        checkEnabledCipherSuites(cipherSuites);
        List<String> opensslSuites = new ArrayList<String>();
        for (int i = 0; i < cipherSuites.length; i++) {
            String cipherSuite = cipherSuites[i];
            if (cipherSuite.equals(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                continue;
            }
            if (cipherSuite.equals(TLS_FALLBACK_SCSV)) {
                SSL_set_mode(ssl, NativeConstants.SSL_MODE_SEND_FALLBACK_SCSV);
                continue;
            }
            opensslSuites.add(cipherSuiteFromJava(cipherSuite));
        }
        SSL_set_cipher_lists(ssl, opensslSuites.toArray(new String[opensslSuites.size()]));
    }

    static String[] checkEnabledCipherSuites(String[] cipherSuites) {
        if (cipherSuites == null) {
            throw new IllegalArgumentException("cipherSuites == null");
        }
        // makes sure all suites are valid, throwing on error
        for (int i = 0; i < cipherSuites.length; i++) {
            if (cipherSuites[i] == null) {
                throw new IllegalArgumentException("cipherSuites[" + i + "] == null");
            }
            if (cipherSuites[i].equals(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
                    || cipherSuites[i].equals(TLS_FALLBACK_SCSV)) {
                continue;
            }
            if (SUPPORTED_CIPHER_SUITES_SET.contains(cipherSuites[i])) {
                continue;
            }

            // For backwards compatibility, it's allowed for |cipherSuite| to
            // be an OpenSSL-style cipher-suite name.
            if (SUPPORTED_LEGACY_CIPHER_SUITES_SET.contains(cipherSuites[i])) {
                // TODO log warning about using backward compatability
                continue;
            }
            throw new IllegalArgumentException(
                    "cipherSuite " + cipherSuites[i] + " is not supported.");
        }
        return cipherSuites;
    }

    static native void SSL_set_accept_state(long sslNativePointer);

    static native void SSL_set_connect_state(long sslNativePointer);

    static native void SSL_set_verify(long sslNativePointer, int mode);

    static native void SSL_set_session(long sslNativePointer, long sslSessionNativePointer)
            throws SSLException;

    static native void SSL_set_session_creation_enabled(
            long sslNativePointer, boolean creationEnabled) throws SSLException;

    static native boolean SSL_session_reused(long sslNativePointer);

    static native void SSL_accept_renegotiations(long sslNativePointer) throws SSLException;

    static native void SSL_set_tlsext_host_name(long sslNativePointer, String hostname)
            throws SSLException;
    static native String SSL_get_servername(long sslNativePointer);

    static native void SSL_do_handshake(
            long sslNativePointer, FileDescriptor fd, SSLHandshakeCallbacks shc, int timeoutMillis)
            throws SSLException, SocketTimeoutException, CertificateException;

    public static native String SSL_get_current_cipher(long sslNativePointer);

    public static native String SSL_get_version(long sslNativePointer);

    /**
     * Returns the peer certificate chain.
     */
    static native byte[][] SSL_get0_peer_certificates(long sslNativePointer);

    /**
     * Reads with the native SSL_read function from the encrypted data stream
     * @return -1 if error or the end of the stream is reached.
     */
    static native int SSL_read(long sslNativePointer, FileDescriptor fd, SSLHandshakeCallbacks shc,
            byte[] b, int off, int len, int readTimeoutMillis) throws IOException;

    /**
     * Writes with the native SSL_write function to the encrypted data stream.
     */
    static native void SSL_write(long sslNativePointer, FileDescriptor fd,
            SSLHandshakeCallbacks shc, byte[] b, int off, int len, int writeTimeoutMillis)
            throws IOException;

    static native void SSL_interrupt(long sslNativePointer);
    static native void SSL_shutdown(
            long sslNativePointer, FileDescriptor fd, SSLHandshakeCallbacks shc) throws IOException;

    static native int SSL_get_shutdown(long sslNativePointer);

    static native void SSL_free(long sslNativePointer);

    static native byte[] SSL_SESSION_session_id(long sslSessionNativePointer);

    static native long SSL_SESSION_get_time(long sslSessionNativePointer);

    static native long SSL_get_time(long sslNativePointer);

    static native long SSL_set_timeout(long sslNativePointer, long millis);

    static native long SSL_get_timeout(long sslNativePointer);

    static native long SSL_SESSION_get_timeout(long sslSessionNativePointer);

    static native byte[] SSL_session_id(long sslNativePointer);

    static native String SSL_SESSION_get_version(long sslSessionNativePointer);

    static native String SSL_SESSION_cipher(long sslSessionNativePointer);

    static native void SSL_SESSION_up_ref(long sslSessionNativePointer);

    static native void SSL_SESSION_free(long sslSessionNativePointer);

    static native byte[] i2d_SSL_SESSION(long sslSessionNativePointer);

    static native long d2i_SSL_SESSION(byte[] data) throws IOException;

    /**
     * A collection of callbacks from the native OpenSSL code that are
     * related to the SSL handshake initiated by SSL_do_handshake.
     */
    interface SSLHandshakeCallbacks {
        /**
         * Verify that the certificate chain is trusted.
         *
         * @param certificateChain chain of X.509 certificates in their encoded form
         * @param authMethod auth algorithm name
         *
         * @throws CertificateException if the certificate is untrusted
         */
        @SuppressWarnings("unused")
        void verifyCertificateChain(byte[][] certificateChain, String authMethod)
                throws CertificateException;

        /**
         * Called on an SSL client when the server requests (or
         * requires a certificate). The client can respond by using
         * SSL_use_certificate and SSL_use_PrivateKey to set a
         * certificate if has an appropriate one available, similar to
         * how the server provides its certificate.
         *
         * @param keyTypes key types supported by the server,
         * convertible to strings with #keyType
         * @param asn1DerEncodedX500Principals CAs known to the server
         */
        @SuppressWarnings("unused")
        void clientCertificateRequested(byte[] keyTypes, byte[][] asn1DerEncodedX500Principals)
                throws CertificateEncodingException, SSLException;

        /**
         * Gets the key to be used in client mode for this connection in Pre-Shared Key (PSK) key
         * exchange.
         *
         * @param identityHint PSK identity hint provided by the server or {@code null} if no hint
         *        provided.
         * @param identity buffer to be populated with PSK identity (NULL-terminated modified UTF-8)
         *        by this method. This identity will be provided to the server.
         * @param key buffer to be populated with key material by this method.
         *
         * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
         *         error occurred in which case the handshake will be aborted.
         */
        int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key);

        /**
         * Gets the key to be used in server mode for this connection in Pre-Shared Key (PSK) key
         * exchange.
         *
         * @param identityHint PSK identity hint provided by this server to the client or
         *        {@code null} if no hint was provided.
         * @param identity PSK identity provided by the client.
         * @param key buffer to be populated with key material by this method.
         *
         * @return number of bytes this method stored in the {@code key} buffer or {@code 0} if an
         *         error occurred in which case the handshake will be aborted.
         */
        int serverPSKKeyRequested(String identityHint, String identity, byte[] key);

        /**
         * Called when SSL state changes. This could be handshake completion.
         */
        @SuppressWarnings("unused")
        void onSSLStateChange(int type, int val);

        /**
         * Called when a new session has been established and may be added to the session cache.
         * The callee is responsible for incrementing the reference count on the returned session.
         */
        @SuppressWarnings("unused")
        void onNewSessionEstablished(long sslSessionNativePtr);

        /**
         * Called for servers where TLS < 1.3 (TLS 1.3 uses session tickets rather than
         * application session caches).
         *
         * <p/>Looks up the session by ID in the application's session cache. If a valid session
         * is returned, this callback is responsible for incrementing the reference count (and any
         * required synchronization).
         *
         * @param id the ID of the session to find.
         * @return the cached session or {@code 0} if no session was found matching the given ID.
         */
        @SuppressWarnings("unused")
        long serverSessionRequested(byte[] id);
    }

    static native String SSL_CIPHER_get_kx_name(long cipherAddress);

    static native String[] get_cipher_names(String selection);

    static native byte[] get_ocsp_single_extension(
            byte[] ocspResponse, String oid, long x509Ref, long issuerX509Ref);

    /**
     * Returns the starting address of the memory region referenced by the provided direct
     * {@link Buffer} or {@code 0} if the provided buffer is not direct or if such access to direct
     * buffers is not supported by the platform.
     *
     * <p>NOTE: This method ignores the buffer's current {@code position}.
     */
    static native long getDirectBufferAddress(Buffer buf);

    static native long SSL_BIO_new(long ssl) throws SSLException;

    static native int SSL_get_error(long ssl, int ret);

    static native void SSL_clear_error();

    static native int SSL_pending_readable_bytes(long ssl);

    static native int SSL_pending_written_bytes_in_BIO(long bio);

    /**
     * Returns the maximum overhead, in bytes, of sealing a record with SSL.
     */
    static native int SSL_max_seal_overhead(long ssl);

    /**
     * Enables ALPN for this TLS endpoint and sets the list of supported ALPN protocols in
     * wire-format (length-prefixed 8-bit strings).
     */
    static native void setApplicationProtocols(
            long sslNativePointer, boolean client, byte[] protocols) throws IOException;

    /**
     * Called for a server endpoint only. Enables ALPN and sets a BiFunction that will
     * be called to delegate protocol selection to the application. Calling this method overrides
     * {@link #setApplicationProtocols(long, boolean, byte[])}.
     */
    static native void setApplicationProtocolSelector(
            long sslNativePointer, ApplicationProtocolSelectorAdapter selector) throws IOException;

    /**
     * Returns the selected ALPN protocol. If the server did not select a
     * protocol, {@code null} will be returned.
     */
    static native byte[] getApplicationProtocol(long sslNativePointer);

    /**
     * Variant of the {@link #SSL_do_handshake} used by {@link ConscryptEngine}. This differs
     * slightly from the raw BoringSSL API in that it returns the SSL error code from the
     * operation, rather than the return value from {@code SSL_do_handshake}. This is done in
     * order to allow to properly handle SSL errors and propagate useful exceptions.
     *
     * @return Returns the SSL error code for the operation when the error was {@code
     * SSL_ERROR_NONE}, {@code SSL_ERROR_WANT_READ}, or {@code SSL_ERROR_WANT_WRITE}.
     * @throws IOException when the error code is anything except those returned by this method.
     */
    static native int ENGINE_SSL_do_handshake(long ssl, SSLHandshakeCallbacks shc)
            throws IOException;

    /**
     * Variant of the {@link #SSL_read} for a direct {@link java.nio.ByteBuffer} used by {@link
     * ConscryptEngine}.
     *
     * @return if positive, represents the number of bytes read into the given buffer.
     * Returns {@code -SSL_ERROR_WANT_READ} if more data is needed. Returns
     * {@code -SSL_ERROR_WANT_WRITE} if data needs to be written out to flush the BIO.
     *
     * @throws java.io.InterruptedIOException if the read was interrupted.
     * @throws java.io.EOFException if the end of stream has been reached.
     * @throws CertificateException if the application's certificate verification callback failed.
     * Only occurs during handshake processing.
     * @throws SSLException if any other error occurs.
     */
    static native int ENGINE_SSL_read_direct(long sslNativePointer, long address, int length,
            SSLHandshakeCallbacks shc) throws IOException, CertificateException;

    /**
     * Variant of the {@link #SSL_write} for a direct {@link java.nio.ByteBuffer} used by {@link
     * ConscryptEngine}. This version does not lock or and does no error pre-processing.
     */
    static native int ENGINE_SSL_write_direct(long sslNativePointer, long address, int length,
            SSLHandshakeCallbacks shc) throws IOException;

    /**
     * Writes data from the given direct {@link java.nio.ByteBuffer} to the BIO.
     */
    static native int ENGINE_SSL_write_BIO_direct(long sslRef, long bioRef, long pos, int length,
            SSLHandshakeCallbacks shc) throws IOException;

    /**
     * Writes data from the given array to the BIO.
     */
    static native int ENGINE_SSL_write_BIO_heap(long sslRef, long bioRef, byte[] sourceJava,
            int sourceOffset, int sourceLength, SSLHandshakeCallbacks shc)
            throws IOException, IndexOutOfBoundsException;

    /**
     * Reads data from the given BIO into a direct {@link java.nio.ByteBuffer}.
     */
    static native int ENGINE_SSL_read_BIO_direct(long sslRef, long bioRef, long address, int len,
            SSLHandshakeCallbacks shc) throws IOException;

    /**
     * Reads data from the given BIO into an array.
     */
    static native int ENGINE_SSL_read_BIO_heap(long sslRef, long bioRef, byte[] destJava,
            int destOffset, int destLength, SSLHandshakeCallbacks shc)
            throws IOException, IndexOutOfBoundsException;

    /**
     * Variant of the {@link #SSL_shutdown} used by {@link ConscryptEngine}. This version does not
     * lock.
     */
    static native void ENGINE_SSL_shutdown(long sslNativePointer, SSLHandshakeCallbacks shc)
            throws IOException;

    /**
     * Used for testing only.
     */
    static native int BIO_read(long bioRef, byte[] buffer) throws IOException;
    static native void BIO_write(long bioRef, byte[] buffer, int offset, int length)
            throws IOException, IndexOutOfBoundsException;
    static native long ERR_peek_last_error();
    static native long SSL_clear_mode(long ssl, long mode);
    static native long SSL_get_mode(long ssl);
    static native long SSL_get_options(long ssl);
    static native long SSL_get1_session(long ssl);
}
