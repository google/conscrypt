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

package org.conscrypt.java.security.cert;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// android-add: import libcore.junit.util.EnableDeprecatedBouncyCastleAlgorithmsRule;

import org.conscrypt.TestUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import tests.util.Pair;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class X509CertificateTest {
    // android-add: Allow access to deprecated BC algorithms.

    private static final String VALID_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIFMjCCAxqgAwIBAgIJAL0mG5fOeJ7xMA0GCSqGSIb3DQEBCwUAMC0xCzAJBgNV\n"
            + "BAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoMBFRlc3QwIBcNMTgwOTE3\n"
            + "MTIxNzU3WhgPMjExODA4MjQxMjE3NTdaMC0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQH\n"
            + "DAZMb25kb24xDTALBgNVBAoMBFRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n"
            + "ggIKAoICAQDCMhBrRAGGw+n2GdctBr/cEK4FZA6ajiHjihgpCHoSBdyL4R2jGKLS\n"
            + "g0WgaMXa1HpkKN7LcIySosEBPlmcRkr1RqbEvQStOSvoFCXYvtx3alM6HTbXMcDR\n"
            + "mqoKoABP6LXsPSoMWIgqMtP2X9EOppzHVIK1yFYFfbIlvYUV2Ka+MuMe0Vh5wvD1\n"
            + "4GanPb+cWSKgdRSVQovCCMY3yWtZKVEaxRpCsk/mYYIFWz0tcgMjIKwDx1XXgiAV\n"
            + "nU6NK43xbaw3XhtnaD/pv9lhTTbNrlcln9LjTD097BaK4R+1AEPHnpfxA9Ui3upn\n"
            + "kbsNUdGdOB0ksZi/vd7lh833YgquQUIAhYrbfvq/HFCpVV1gljzlS3sqULYpLE//\n"
            + "i3OsuL2mE+CYIJGpIi2GeJJWXciNMTJDOqTn+fRDtVb4RPp4Y70DJirp7XzaBi3q\n"
            + "H0edANCzPSRCDbZsOhzIXhXshldiXVRX666DDlbMQgLTEnNKrkwv6DmU8o15XQsb\n"
            + "8k1Os2YwXmkEOxUQ7AJZXVTZSf6UK9Znmdq1ZrHjybMfRUkHVxJcnKvrxfryralv\n"
            + "gzfvu+D6HuxrCo3Ojqa+nDgIbxKEBtdrcsMhq1jWPFhjwo1fSadAkKOfdCAuXJRD\n"
            + "THg3b4Sf+W7Cpc570YHrIpBf7WFl2XsPcEM0mJZ5+yATASCubNozQwIDAQABo1Mw\n"
            + "UTAdBgNVHQ4EFgQUES0hupZSqY21JOba10QyZuxm91EwHwYDVR0jBBgwFoAUES0h\n"
            + "upZSqY21JOba10QyZuxm91EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\n"
            + "AAOCAgEABTN5S30ng/RMpBweDm2N561PdpaCdiRXtAFCRVWR2mkDYC/Xj9Vqe6be\n"
            + "PyM7L/5OKYVjzF1yJu67z/dx+ja5o+41g17jdqla7hyPx+9B4uRyDh+1KJTa+duj\n"
            + "mw/aA1LCr6O6W4WizDOsChJ6FaB2Y1+GlFnKWb5nUdhVJqXQE1WOX9dZnw8Y4Npd\n"
            + "VmAsjWot0BZorJrt3fwfcv3QfA896twkbo7Llv/8qzg4sXZXZ4ZtgAOqnPngiSn+\n"
            + "JT/vYCXZ406VvAFpFqMcVz2dO/VGuL8lGIMHRKNyafrsV81EzH1W/XmRWOgvgj6r\n"
            + "yQI63ln/AMY72HQ97xLkE1xKunGz6bK5Ug5+O43Uftc4Mb6MUgzo+ZqEQ3Ob+cAV\n"
            + "cvjmtwDaPO/O39O5Xq0tLTlkn2/cKf4OQ6S++GDxzyRVHh5JXgP4j9+jfZY57Woy\n"
            + "R1bE7N50JjY4cDermBJKdlBIjL7UPhqmLyaG7V0hBitFlgGBUCcJtJOV0xYd5aF3\n"
            + "pxNkvMXhBmh95fjxJ0cJjpO7tN1RAwtMMNgsl7OUbuVRQCHOPW5DgP5qY21jDeRn\n"
            + "BY82382l+9QzykmJLI5MZnmj4BA9uIDCwMtoTTvP++SsvhUAbuvh7MOOUQL0EY4m\n"
            + "KStYq7X9PKseN+PvmfeoffIKc5R/Ha39oi7cGMVHCr8aiEhsf94=\n"
            + "-----END CERTIFICATE-----";

    // Self-signed certificate using ECDSA over curve P-256 with SHA256.
    private static final String CERT_WITH_ECDSA = "-----BEGIN CERTIFICATE-----\n"
            + "MIICDzCCAbYCCQDlsuMWvgQzhTAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCVVMx\n"
            + "EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT\n"
            + "BgNVBAoMDEdvb2dsZSwgSW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAh\n"
            + "BgkqhkiG9w0BCQEWFGdvbGFuZy1kZXZAZ21haWwuY29tMB4XDTEyMDUyMTAwMTkx\n"
            + "NloXDTIyMDUxOTAwMTkxNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp\n"
            + "Zm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUs\n"
            + "IEluYy4xFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRn\n"
            + "b2xhbmctZGV2QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPMt\n"
            + "2ErhxAty5EJRu9yM+MTy+hUXm3pdW1ensAv382KoGExSXAFWP7pjJnNtHO+XSwVm\n"
            + "YNtqjcAGFKpweoN//kQwCgYIKoZIzj0EAwIDRwAwRAIgIYSaUA/IB81gjbIw/hUV\n"
            + "70twxJr5EcgOo0hLp3Jm+EYCIFDO3NNcgmURbJ1kfoS3N/0O+irUtoPw38YoNkqJ\n"
            + "h5wi\n"
            + "-----END CERTIFICATE-----\n";

    // From https://github.com/golang/go/blob/master/src/crypto/x509/x509_test.go
    private static final String CERT_WITH_RSA_PSS = "-----BEGIN CERTIFICATE-----\n"
            + "MIIGHjCCA9KgAwIBAgIBdjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUA\n"
            + "oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwbjELMAkGA1UEBhMC\n"
            + "SlAxHDAaBgNVBAoME0phcGFuZXNlIEdvdmVybm1lbnQxKDAmBgNVBAsMH1RoZSBN\n"
            + "aW5pc3RyeSBvZiBGb3JlaWduIEFmZmFpcnMxFzAVBgNVBAMMDmUtcGFzc3BvcnRD\n"
            + "U0NBMB4XDTEzMDUxNDA1MDczMFoXDTI5MDUxNDA1MDczMFowbjELMAkGA1UEBhMC\n"
            + "SlAxHDAaBgNVBAoME0phcGFuZXNlIEdvdmVybm1lbnQxKDAmBgNVBAsMH1RoZSBN\n"
            + "aW5pc3RyeSBvZiBGb3JlaWduIEFmZmFpcnMxFzAVBgNVBAMMDmUtcGFzc3BvcnRD\n"
            + "U0NBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx/E3WRVxcCDXhoST\n"
            + "8nVSLjW6hwM4Ni99AegWzcGtfGFo0zjFA1Cl5URqxauvYu3gQgQHBGA1CovWeGrl\n"
            + "yVSRzOL1imcYsSgLOcnhVYB3Xcrof4ebv9+W+TwNdc9YzAwcj8rNd5nP6PKXIQ+W\n"
            + "PCkEOXdyb80YEnxuT+NPjkVfFSPBS7QYZpvT2fwy4fZ0eh48253+7VleSmTO0mqj\n"
            + "7TlzaG56q150SLZbhpOd8jD8bM/wACnLCPR88wj4hCcDLEwoLyY85HJCTIQQMnoT\n"
            + "UpqyzEeupPREIm6yi4d8C9YqIWFn2YTnRcWcmMaJLzq+kYwKoudfnoC6RW2vzZXn\n"
            + "defQs68IZuK+uALu9G3JWGPgu0CQGj0JNDT8zkiDV++4eNrZczWKjr1YnAL+VbLK\n"
            + "bApwL2u19l2WDpfUklimhWfraqHNIUKU6CjZOG31RzXcplIj0mtqs0E1r7r357Es\n"
            + "yFoB28iNo4cz1lCulh0E4WJzWzLZcT4ZspHHRCFyvYnXoibXEV1nULq8ByKKG0FS\n"
            + "7nn4SseoV+8PvjHLPhmHGMvi4mxkbcXdV3wthHT1/HXdqY84A4xHWt1+sB/TpTek\n"
            + "tDhFlEfcUygvTu58UtOnysomOVVeERmi7WSujfzKsGJAJYeetiA5R+zX7BxeyFVE\n"
            + "qW0zh1Tkwh0S8LRe5diJh4+6FG0CAwEAAaNfMF0wHQYDVR0OBBYEFD+oahaikBTV\n"
            + "Urk81Uz7kRS2sx0aMA4GA1UdDwEB/wQEAwIBBjAYBgNVHSAEETAPMA0GCyqDCIaP\n"
            + "fgYFAQEBMBIGA1UdEwEB/wQIMAYBAf8CAQAwQQYJKoZIhvcNAQEKMDSgDzANBglg\n"
            + "hkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgA4IC\n"
            + "AQAaxWBQn5CZuNBfyzL57mn31ukHUFd61OMROSX3PT7oCv1Dy+C2AdRlxOcbN3/n\n"
            + "li0yfXUUqiY3COlLAHKRlkr97mLtxEFoJ0R8nVN2IQdChNQM/XSCzSGyY8NVa1OR\n"
            + "TTpEWLnexJ9kvIdbFXwUqdTnAkOI0m7Rg8j+E+lRRHg1xDAA1qKttrtUj3HRQWf3\n"
            + "kNTu628SiMvap6aIdncburaK56MP7gkR1Wr/ichOfjIA3Jgw2PapI31i0GqeMd66\n"
            + "U1+lC9FeyMAJpuSVp/SoiYzYo+79SFcVoM2yw3yAnIKg7q9GLYYqzncdykT6C06c\n"
            + "15gWFI6igmReAsD9ITSvYh0jLrLHfEYcPTOD3ZXJ4EwwHtWSoO3gq1EAtOYKu/Lv\n"
            + "C8zfBsZcFdsHvsSiYeBU8Oioe42mguky3Ax9O7D805Ek6R68ra07MW/G4YxvV7IN\n"
            + "2BfSaYy8MX9IG0ZMIOcoc0FeF5xkFmJ7kdrlTaJzC0IE9PNxNaH5QnOAFB8vxHcO\n"
            + "FioUxb6UKdHcPLR1VZtAdTdTMjSJxUqD/35Cdfqs7oDJXz8f6TXO2Tdy6G++YUs9\n"
            + "qsGZWxzFvvkXUkQSl0dQQ5jO/FtUJcAVXVVp20LxPemfatAHpW31WdJYeWSQWky2\n"
            + "+f9b5TXKXVyjlUL7uHxowWrT2AtTchDH22wTEtqLEF9Z3Q==\n"
            + "-----END CERTIFICATE-----\n";

    // Self-signed certificate using Ed25519
    private static final String CERT_WITH_ED25519 = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBWzCCAQ2gAwIBAgIUDIPYISuCyyOYI2Pi95eKQ1vzvZIwBQYDK2VwMCMxITAf\n"
            + "BgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZpY2F0ZTAeFw0xOTA1MDYxNzI3MTZa\n"
            + "Fw0xOTA2MDUxNzI3MTZaMCMxITAfBgNVBAMMGEVkMjU1MTkgdGVzdCBjZXJ0aWZp\n"
            + "Y2F0ZTAqMAUGAytlcAMhADYpxWwNTxRsgdD/ddNqcF9pzQ9NZtXamH6CSYmjijz6\n"
            + "o1MwUTAdBgNVHQ4EFgQUCTs6nUop2JX/aL57Q1Ry4K2i464wHwYDVR0jBBgwFoAU\n"
            + "CTs6nUop2JX/aL57Q1Ry4K2i464wDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBT\n"
            + "pVgcLDsqnqydTqUdX11tprUI3hKC85cgrvrYmPQagzJrkfUkHcQgfyziTdoTO21U\n"
            + "GtKoKNxgudT0eEs8HJEA\n"
            + "-----END CERTIFICATE-----\n";

    // Self-signed certificate using ML-DSA-44
    private static final String CERT_WITH_MLDSA44 = "-----BEGIN CERTIFICATE-----\n"
            + "MIIPlDCCBgqgAwIBAgIUFZ/+byL9XMQsUk32/V4o0N44804wCwYJYIZIAWUDBAMR\n"
            + "MCIxDTALBgNVBAoTBElFVEYxETAPBgNVBAMTCExBTVBTIFdHMB4XDTIwMDIwMzA0\n"
            + "MzIxMFoXDTQwMDEyOTA0MzIxMFowIjENMAsGA1UEChMESUVURjERMA8GA1UEAxMI\n"
            + "TEFNUFMgV0cwggUyMAsGCWCGSAFlAwQDEQOCBSEA17K0clSq4NtF55MNSpjSyX2P\n"
            + "E5fReJ2voXAksxbpvslPyZRtQvGbeadBO7qjPnFJy0LtURVpOsBB+suYit61/g4d\n"
            + "hjEYSZW1ksOX0ilOLhT5CqQUujgmiZrEP0zMrLwm6agyuVEY1ctDPL75ZgsAE44I\n"
            + "F/YediyidMNq1VTrIqrBFi5KsBrLoeOMTv2PgLZbMz0PcuVd/nHOnB67mInnxWEG\n"
            + "wP1zgDoq7P6v3teqPLLO2lTRK9jNNqeM+XWUO0er0l6ICsRS5XQu0ejRqCr6huWQ\n"
            + "x1jBWuTShA2SvKGlCQ9ASWWX/KfYuVE/GhvabpUKqpjeRnUH1KT1pPBZkhZYLDVy\n"
            + "9i7aiQWrNYFnDEoCd3oz4Mpylf2PT/bRoKOnaD1l9fX3/GDaAj6CbF+SFEwC99G6\n"
            + "EHWYdVPqk2f8122ZC3+pnNRa/biDbUPkWfUYffBYR5cJoB6mg1k1+nBGCZDNPcG6\n"
            + "QBupS6sd3kGsZ6szGdysoGBI1MTu8n7hOpwX0FOPQw8tZC3CQVZg3niHfY2KvHJS\n"
            + "OXjAQuQoX0MZhGxEEmJCl2hEwQ5Va6IVtacZ5Z0MayqW05hZBx/cws3nUkp77a5U\n"
            + "6FsxjoVOj+Ky8+36yXGRKCcKr9HlBEw6T9r9n/MfkHhLjo5FlhRKDa9YZRHT2ZYr\n"
            + "nqla8Ze05fxg8rHtFd46W+9fib3HnZEFHZsoFudPpUUx79wcvnTUSIV/R2vNWPIc\n"
            + "C2U7O3ak4HamVZowJxhVXMY/dIWaq6uSXwI4YcqM0Pe62yhx9n1VMm10URNa1F9K\n"
            + "G6aRGPuyyKMO7JOS7z+XcGbJrdXHEMxkexUU0hfZWMcBfD6Q/SDATmdLkEhuk3Cj\n"
            + "GgAdMvRzl55JBnSefkd/oLdFCPil8jeDErg8Jb04jKCw//dHi69CtxZn7arJfEax\n"
            + "KWQ+WG5bBVoMIRlG1PNuZ1vtWGD6BCoxXZgmFk1qkjfDWl+/SVSQpb1N8ki5XEqu\n"
            + "d4S2BWcxZqxCRbW0sIKgnpMj5i8geMW3Z4NEbe/XNq06NwLUmwiYRJAKYYMzl7xE\n"
            + "GbMNepegs4fBkRR0xNQbU+Mql3rLbw6nXbZbs55Z5wHnaVfe9vLURVnDGncSK1IE\n"
            + "47XCGfFoixTtC8C4AbPm6C3NQ+nA6fQXRM2YFb0byIINi7Ej8E+s0bG2hd1aKxuN\n"
            + "u/PtkzZw8JWhgLTxktCLELj6u9/MKyRRjjLuoKXgyQTKhEeACD87DNLQuLavZ7w1\n"
            + "W5SUAl3HsKePqA46Lb/rUTKIUdYHgZjpSTZRrnh+wCUfkiujDp9R32Km1yeEzz3S\n"
            + "BTkxdt+jJKUSvZSXCjbdNKUUqGeR8Os28BRbCatkZRtKAxOymWEaKhxIiRYnWYdo\n"
            + "oxFAYLpEQ0ht9RUioc6IswmFwhb45u0XjdVnswSg1Mr7qIKig0LxepqiauWNtjAI\n"
            + "PSw1j99WbD9dYqQoVnvJ6ozpXKoPNUdLC/qPM5olCrTfzyCDvo7vvBBV4Y/hU3Du\n"
            + "yyYFZtg/8GshGq7EPKKbVMzQD4gVokZe8LRlFcx+QfMSTwnv/3OTCatYspoUWaAL\n"
            + "zlA46TjJZ49y6w5O5f2q5m2fhXP8l/xCtJWfS/i2HXhDPoawM11ukZHE2L9IezkF\n"
            + "wQjP1qwksM633LfPUfhNDtaHuV6uscUzwG8NlwI9kqcIJYN7Wbpst9TlawqHwgOG\n"
            + "KujzFbpZJejt76Z5NpoiAnZhUfFqll+fgeznbMBwtVhp5NuXhM8FyDCzJCyDEqNC\n"
            + "MEAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFDKa\n"
            + "B7H6u0j1KjCfEaGJj4SOIyL/MAsGCWCGSAFlAwQDEQOCCXUAZ6iVH8MI4S9oZ2Ef\n"
            + "3CVL9Ly1FPf18v3rcvqOGgMAYWd7hM0nVZfYMVQZWWaxQWcMsOiBE0YNl4oaejiV\n"
            + "wRykGZV3XAnWTd60e8h8TovxyTJ/xK/Vw3hlU+F9YpsPJxQnZUgUMrXnzNC6YeUc\n"
            + "rT3Y+Vk4wjXr7O6vixauM2bzAMU1jse+nrI6HqGj2lhoZwTwSD+Wim5LH4lnCgE0\n"
            + "s2oY1scn3JsCexJ5R5OkjHq2bt9XrBgRORTADQoRtlplL0d3Eze/dDZm/Klby9OR\n"
            + "Ia4HUL7FWtWoy86Y5TiuUjlH1pKZdjMPyj/JXAHRQDtJ5cuoGBL0NlDdATEJNCee\n"
            + "zQfMqzTCyjCn091QkuFjDhQjzJ+sQ6G02w49lw8Kpm1ASuh7BLTPcuz7Z+rLpNjN\n"
            + "jmW67rR6+hHMK474mSKIZnuO3vVKnidntjLhSYc1soxvYPCLWWnl4m3XyjlrnlzD\n"
            + "4Soec2I2AjKNZKCO9KKa81cRzIcNJjc7sbnrLv/hKXNUTESn4s3yAyRPU7N6bVIy\n"
            + "N9ifBvb1U07WMRPI8A7/f9zVCaLYx87ym9P7GGpMjDYrPUQpOaKQdu4ycWuPrlEA\n"
            + "2BoHIVzbHHm9373BT1LjcxjR5SbbhNFg+42hwG284VlVzcLW/XiipaWN8jnONmxt\n"
            + "kLMui9R/wf0TCehilMDDtRznfm37b2ci5o9MP/LrTDRpMVBudDuwIZmLgPQ/bj08\n"
            + "n+VHd8D2WADpR/kEMpDhSwG2P44mwwE4CUKGbHS0qQLOSRwMlQVEzwxpOOrLMusw\n"
            + "JmzoLE0KNsUR6o/3xAlUmjqCZMqYPYxtXgNfJEJDp3V1iqyZK1iES3EQ0/h8m7oZ\n"
            + "3YqNKrEpTgVV7EmVpUjcVszjWgXcSKynVVsWQd3j0Zf83zXRLwmq8+anJ3XNGCSa\n"
            + "IecO2sZxDbaiHhwFYRkt0BGRM2QM//IPMYeXhRa/1svmbOEHGxJG9LqTffkBs+01\n"
            + "Bp7r3/9lRZ+5t3eukpinpJrCT0AgeV3l3ujbzyCiQbboFDaPS4+kKvi+iS2eHjiu\n"
            + "S/WkfP1Go5jksxhkceJFNPsTmGCyXGPy2/haU9hkiMg9/wmuIKm/gxRfIBh/DoIr\n"
            + "1HWZjTuWcBGWTu2NuXeAVO/MbMtpB0u6mWYktHQcVxA2LenU+N5LEPbbHp+AmPQC\n"
            + "RZPqBziTyx/nuVnFD+/EAbPKzeqMKhcTW6nfkKt/Md4zmi1vhWxx7c+wDlo9cyAf\n"
            + "vsS0p5uXKK1wzaC4mBIVdPYNlZtAjBCK8asKpH3/NyYJ8xhsBjxXLLiQifKiGOpA\n"
            + "LLBy/LyJWmo4R4zkAtUILD4FcsIyLMIJlsqWjaNdey7bwGI75hZQkBIF8QJxFVtT\n"
            + "n4HQBtuNe2ek7e72d+bayceJvlUAFXTu6oeX9/UuS7AhuY4giNzI1pNOgNwWXRxx\n"
            + "REmwvPrzJatZZ7cwfsKTezSSQlv2O4q70+2X2h0VtUg/pkz3GknE07S3ggDR9Qkg\n"
            + "bywQS/42luPIADbbAKXhHaBaX/TaD/uZVn+BOZ5sqWmxEbbHtvzlSea02J1Fk4Hq\n"
            + "kWbpuzByCJ25SuDRr+Xyn84ZDnetumQ0lBkc2ro+rZKXw8YGMyt0aX8ZwJxL4qNB\n"
            + "/WFFEproVsOru8G7iwXgt4QP8WRBSp2kTlQUbNTF3gxOTsslkUErTnvcRQ0GpK06\n"
            + "DRQG8wbjgewpHyw7O8Sfi34EjAzic0gwtIp501/MWmKpRUgAow9LPreiaLq2TBIQ\n"
            + "DXEhUb9fEhY77QKeir8cpue3sShqcz9TLa5REJGqsP/8/URk7lZjiI+YWbRLp2U2\n"
            + "D//0NPEq8fxrzNtacZRxSdx2id/yTWumtj5swjFA4yk0tunadltDMgEYuKgR+Jw9\n"
            + "G3/yFTDnepHK41V6x8eE/4JjUAvIJWADDWxudO7oF/wsY0AnUuWe9DkW09g8IWhk\n"
            + "NukDTdpsl08hCLF06qH3MSHJrdUAzs2GGLMCvtrXK2L3k70PcLqMXhbPSr7d1RGW\n"
            + "gW0BlRfR4l+2LJ952SMv3xzuxgT43aX3FFVBxXk7nFrhWJWIpJpuYXRhTqASkzoZ\n"
            + "KzsIRyW0ZbsaIsy0tgzzyhQvdoOoJn+2sKjcCzpfY6tgRD9sfucOm1sGet/cM5YP\n"
            + "iJYei2qKMeYcvACWiI8GNGY37OzhlikbleO4xXnfJwEOYx66NjTHZqkz1/TiCBGU\n"
            + "a7h+l/fnut6VfkxS1yZ2r5Gsdx7DUfNkEeKyzIMnYRA3zw3047lHqH714rV5VbE3\n"
            + "yYEQWvdtYlHMFM2z9DDta59RRATOemm7AA1fYsfodrV/QPJi5qPmvpHtCvfItbdL\n"
            + "Fg88Zh1zV5nV+0doUTXFVR9poJRE9fASlfU5qCJ9Jx5ISfvIkGz1fmfqXhUN9fE7\n"
            + "C0Evl7IYQLguTXFznRvsXvnliwR9Ut/g85JtXUiku4F2ThCBMHBDbov6p128kP+2\n"
            + "7LBgShM4IG80clxon8sWh6y0RLUz1MTamEYZKCXAPZzJoWhbzdNns/QTsjNP8wlu\n"
            + "vBRtdkb6w4Vrm6GO2BXY6pQUBPcoDuymAhfAF9TxRn860OQeMcT/NRsU9Z/8nRnz\n"
            + "3KbAuMTYsQ6qbjuLTDwfF9B4b4YUDQR22z8wlzCNLzgwFlGSI12xhf3ejRlwjGZJ\n"
            + "J/11Up4pEegRS/c+Li2OUvQr9Jxi8XGIdEJZY1T8oVpzDJf3C29gpARWSDAXrFn0\n"
            + "lgZHnqFyebeC1uDW8r/wGtYmI2EC53+FlOF5AFcH+3LzObZzerqwror4UMOA+B5c\n"
            + "QMU5vDv1LFcWLzvJHMXJfCHL5nVSukXCMawr+DbeKjrkseG0UX0gpUbQy0vHIH1K\n"
            + "2geD2xyl3TJ8jCaKOxb/Hu+KfkvtOCsh07TA+cnTV1WHR77svUcMErzHXWOFm8+U\n"
            + "omIXALO1EiDbpu38gERRLkC84eMhRBQjKcdmlcBFsmilt3cfIofypuhMRiIFjIke\n"
            + "00y2GEdQVsZGA/LX1HILqD4dEFDDQI2LPvCG5qe28HTfWspzsqK94IRESzm+Vmdp\n"
            + "IjNzkTyrPI06yMvxaHGajwUtLWCReJOG/uXhswbX7EviVYyqCR4vzDLDVXAulxo/\n"
            + "OsHaQhMX8xYOLXontx7SNCBlu/EEBww5QklKUldgd5igr7bDxsvZ6vHy/wcNIzY3\n"
            + "RUdidnuDkpSm1hIoLz4/SW2Tm6C2u9La5evu7xAfIy1ul8LE3/P0AAAAAAAAAAAA\n"
            + "AAAAABcmOEM=\n"
            + "-----END CERTIFICATE-----\n";

    // Self-signed certificate using ML-DSA-65
    private static final String CERT_WITH_MLDSA65 = "-----BEGIN CERTIFICATE-----\n"
            + "MIIVjTCCCIqgAwIBAgIUFZ/+byL9XMQsUk32/V4o0N44804wCwYJYIZIAWUDBAMS\n"
            + "MCIxDTALBgNVBAoTBElFVEYxETAPBgNVBAMTCExBTVBTIFdHMB4XDTIwMDIwMzA0\n"
            + "MzIxMFoXDTQwMDEyOTA0MzIxMFowIjENMAsGA1UEChMESUVURjERMA8GA1UEAxMI\n"
            + "TEFNUFMgV0cwggeyMAsGCWCGSAFlAwQDEgOCB6EASGg9kZeOMes93biwRzSC0riK\n"
            + "X2JZSf2PWKVh5pa9TCfQWzjbsu3wHmZO/YG+HqiTaIzmiqLVHFlY+LvG606J7mfS\n"
            + "wDIJVNVyEsrHIp/x1urwOSi9UVEfjYjYR3NsfeJzDVl45UEHExYJeIZ3Eb9VOaC/\n"
            + "xMNQwr5XK68O4uL7Fsz+oIAo2ZrEmuu3WTfdzhEc2rYv/zzqi6IjPR5W+8XFoecm\n"
            + "3mP63SrwFrEZF3+j2XGi2Sdxc/zlW2d0WvC3wh1Zfb65Pmoy80HEmlqL6eglCI0f\n"
            + "KqRRVdbIrhU2fk6wA7j994UQcZSXOfn/8JAj6vRRBNKoSkWQbu1GcaRNwo0nmHu1\n"
            + "XfaenoVh9hqApyaZUDhl/tm37nKo4XoZxAgUT0spr+9wMcOm2FcWELQsn0ISRaiP\n"
            + "GX4WgSsDEVm2W5aH5bPpNMUiWumKebpz0rOZ1zUQ7/rRnlO4RQ8LqPzhAS/ZjSYK\n"
            + "dKqqE/riSaAGscNPW6C4gvJjeCIvs28ig8JD8P/rXxu0FKCnDVXj1ApWtsvIiuHw\n"
            + "O3sogtmN7qKOFFyd7f2OrxzvLtlKiwUPiWT0bR6g0MKkPg3aYYKtv09u0XW2dCJX\n"
            + "hZvyLzpBfs8fnYkxe15TnVh68WueExPgRRT/pkuos/8rgyH4gRyz+wIsj2ROcKS4\n"
            + "Ci+/7mBKu3N5CR6o5sXHTfwCg2ZrQMB5OHACggShNr9dqVaOt5jTSQOL2wwR4DRF\n"
            + "54R8tQacdc8orGAcd5nZWCEN28siblGv758d5HsHOHPW0/l0Vr7eCFCC50opiyzU\n"
            + "j0swkxVfNmyPpgHGr4WN+jLAhJGyopiH+QM1lJpdbtqmeYgqOpXWv22XCiIfS509\n"
            + "jL84SvgarJXisylOBHiayDcnpdwEVZ+Wr0HYoFNRb+7uvFJ0brarKBngkQhxDYNf\n"
            + "AR+mMGWHKtM01c3/srIxBQfpL8mTrjF9qX9PMJza8PZ+2Z2QIVV2CDhJ+VOyRtf+\n"
            + "2z/bZ2eYUKWtQE5kFH+3z09q7d0Fr7S4NJaNH+iAFJYNzl2UIjZSbhKkeNaeX75p\n"
            + "cDELMIwGhFAYz8eyq0MKE6axrHuwLMy7PZEawvEQaGE/vgKb/c4Cz1zTiVDtcsg5\n"
            + "RO37x1YVr4f4ZMBR88VUVsVBKGOkDAbR2rVivf8FcbjTw5F7vTAIgLul6Zgjm5X6\n"
            + "kbfWQW1POYs6280wmD7TWStNnvfUI2/QD1DZiqU6I1rEFycg932WFyZymAz+j/el\n"
            + "pwJ4PtwroxsiWQFaES/H9GipwvlGQDkALTDvZ4tMt5i8EWIWv3qafBi6A7e1j9B1\n"
            + "FdMRUEnTYUvnoH50QwB1DfHSxYdTOJBZ6vw9eFzN0xwHZIvtwDpcO4rUbQZNWcE9\n"
            + "VzdHKfxOKVNi4qUZEgRTBCi8FSKvoo/1/hZV4wTKW8jCetDgxqOd1N8olWwUs4zJ\n"
            + "NoLO/kArvV6C0pxGTkTrXTe0j8Vo3+DMbo4WuuoF5RNVkPGSlOc+g2ewIW27gVAw\n"
            + "ud5VkT8IA5xCNRxZ5VFd1a+OCJoV5iXo9t7mOThsRkl9eiYyiHdN5YGn3pYptBtE\n"
            + "JBQfl4+4MxII797DxuDeObxXBj89zWxHA3PAiJHqKcvHzG1kg7iIkIOs6GqntRsc\n"
            + "LP5uKtGNl842+8VupC+ul+anrBFIZEeMNm3x67HnsRqQmFBP1Zdb3x9J3HAAK2PB\n"
            + "c5qdJj+61Ac/ap9sK4r0tMMyoQOgz/pd7rLQYso8IV/TYAJr58UWT0pEJO90lIgE\n"
            + "1m9GSHcyyCAseVR4ZHtOpx1ifAhgJMyjVKQfCHezjxmzd0rSCVyNpTsGniHHauLS\n"
            + "AH4WcZ7UAIDTNPfaUun1pZkEOcrwg6lbgz8CrRCgjBptDyYMAHKFvUovR3A6Wu9G\n"
            + "UofSU7GKwiUUMWIQ/1ZoFLEPh6KT1vGZ08OVmZDQwSaLT1DV+fzvu/I3vQwouAGC\n"
            + "1mWXQfFPEL+7IbuhKrYgqiOW9WwGhrTqkBeZAiQhay/orXbEqRSO75qGo2Naaqd7\n"
            + "wdz7b7pZp339qbdTDcDKhkjI2XNzjgG6uPCLSQXoSqRkG9YCQQzZdSAmXy8jHys1\n"
            + "4V6y+gTSvZTVp3q68eDhYQEKmQCH9bRuqYiyvAUS/aD6kj2t1sRcUwHQlINnMmW1\n"
            + "qy4Q9LpSD2u61WSlw9Xie9sID30g4TKWoxgZVMOcZJyUPr4X31wfeq4Kj+EmxHdY\n"
            + "Wl1NZIoNAItq9ejNMb5pqSltTz/SXthvIh5Lk/ZfWSmWdTNiS5I1dQwwcHVQtYU2\n"
            + "0QmnExxaW75KVxVWfBJTSux2YHYe67n64okcd0WJuA5WatVX3e9zZxlrcifqmHDv\n"
            + "Cd3+x51rkxmmh5tSBddr96ulrPM6+1nRf8VOaDg9a+Wgjptm2lPc3gCLspS4WCvR\n"
            + "Ms3MSZWf28IeUnIYgMitA1LHnwOkO72ExM39xsUpAF4efNmjSacWijVWm6XeqBiW\n"
            + "jVqRRmvW5k4gv2JBcZivxOgcKN137UAoIyOYtS+96GvIT0dbkBZxDOKqvBGga026\n"
            + "yQHsFs82XKPy1TgTlIppOg+T55xGyl1abco9KMpQrRi9E/ylUFndmxhfefnEcZak\n"
            + "6BshBLxGCgUeAvLoRE+jQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTAD\n"
            + "AQH/MB0GA1UdDgQWBBQbBWPjzTNGFJyMnrzyOwpOWpAO6jALBglghkgBZQMEAxID\n"
            + "ggzuABGBaGipDGaTS9ux0ZxTpqXcMFNf9tzIZpskKErpMQ6aV8eRhwK1+knGM75H\n"
            + "XVSS2dfuo5FCaBmpJpq1lPQ0lCtN/LulqD3M01O+evbv3WYJch6O5zkUALRH5Xg9\n"
            + "NKps3fGNrf+wyuCjyJn+D/Y75gWpM25S7jXrsu4vu2TNqlzkyzYehJx6zu3B70QJ\n"
            + "0vfBCLthjdBepjQ33aA5bAgJoIMDd3UUJwtDdeYP+WOf6qRq3CaYEigq/hfBb5sY\n"
            + "m6MS6lY8ICDjHve05b2iguECEkeZGXfxSF0w/tIgyhPoRx6PvIuyuVI14a43ttSP\n"
            + "zATqALqoA6nUifcgr+RpWMeNQBMTJlc6EnMXxB+H0wq/ZfVmx7ixgTgOm8kIzcHv\n"
            + "rO6yQkbyrD4hOXsYN7eabJvuZIpFTPyxfG8kwBUl/8Vrp5hl8z9F1fJU3J8bOUha\n"
            + "XmTrHU+gM8oNVrnUHYufcLpJkhiufVWvuXtHsmyvZm9N6nkOCDCkJwUop91d0Pde\n"
            + "2dBHOKcb2L1lWfKy4N43nt9ntldr4s0LieIb1XDFM+eJmMpv6/mb1no7W9koXf+j\n"
            + "zIrbeY9nMGvQW+opV2XA8HEYyJ2iaFrAn9bcyO/CFCsyPRchJ7sO6FfSFISEw6ak\n"
            + "D3hTCMqSaPYk4THepKBi73/PdKcyVXEZLXFTT1wPv+PacRE4rgPlfpWe+6lOtsZW\n"
            + "8AG+FqzLE1Ag87Hj5W1xmTPC0R/47lnsQ+HVWEfMGtt1kCuWqfA9OkQNyK5ogLkK\n"
            + "f1KBYF6Ie5Ay2vw6cKZOlHSmAynwskgqzuPOGAqEUdbomnSbulLH/Xut8YfR0gNH\n"
            + "5q2vzA6lr7Hw6NpCMiH3SJ3+9ST1wDS1KS9HN6gPh8q2Vps67Ezg8BnEsJ2w2Qt1\n"
            + "WfFSXlNtwGZSLLZVcZbk6IRsvg5E19egM7Uozmc621rdZEOU56n24XyWDP3oVJrC\n"
            + "y9/m7mMPesIo5+Sa0oZyG9QYf8mjqckUbS8+z1xFX4s+aJB3bk+ACbJBS2EnJUjM\n"
            + "Pi2vvQ60nU+euOLxRBBizMkShiWUoAsM/1Gk7OM2WU0mdNPsrWVNih4F0LLsxhBl\n"
            + "DBa/7+Kk9X9XqvMaTP+RJU2Z6r0Xhz/0QODSH1aefm2AYCgmv/fUIj8SQsMFxnrb\n"
            + "ocarCVc0BbJLMPrQm71SPsVzZCqHwME+aLDMlTE6Mqj4uR8feilTgK8mclcUgLQL\n"
            + "CsjAM/xT2B3RGVUSx4W21q0FYPy4L9NCyKMfFOg8+3ChmCg5u6XYKncSHltyoEE8\n"
            + "XVDgEKgxONy5huCYPpDo087Ke1AGg6Br6WTmDGwnXOIzyQNMEJlaOZaCCKUqitfu\n"
            + "d+DvAD3+bzk6WTwsj7OMUEeqo5NBUxMR/eWTJRBmVT97f+6SnGld+UBliVi6V/Sx\n"
            + "OeTWQMO9ljKd9lMar8uT/WyyvByUCevHzEAe5YiLMezPS8hw7lu4XRhe+3uD5JsX\n"
            + "854zVKOrraOh1t0sZHlxdNO+656htKo4dO5ObGbqp1tWmvWw5VEcX233yqSnN0vj\n"
            + "+/0l9lUfS7YOYrCQHtbds+gLlL8ZhpBhdcZd/HLwfuShBdvjwRRmNglG5lKF9G1x\n"
            + "qAxLr9ZIuooPKDG9IWD3RRDSuXcBCJcPh1FQ4JVZDgxc2vnraC9ikS7iBdnrcFbM\n"
            + "ASjTvoHNuo5j42aqca8dStxXW4WX9gNd1Ld+ItLA2GaBi1EK+mf+f+37xC46xZ/B\n"
            + "g/kWxT9HYHF5SwxZ7zszZZLSKykJd0ziUIdeYMgZ4Yo6v08SU51/2ZSzAxQW4TZ6\n"
            + "j88YJBsuX8ariqiCKOTF+lHavSK7RjsaN+McvJ0KR6RZw9iBeO9najevlYT1HxZP\n"
            + "KfvVQVWfyhmevOoyo3ZhQP07zORuoXqXOidypQWpY2RS+g7WU+HaFyeFzZAbYFEL\n"
            + "M5Eibh16apEtPOXglDKWTiLNdU6ws0T5ymHNgrAZLtq308RhQkTCFR7/yYnlbcMh\n"
            + "9MApe0Z8/aNFEU3jbmTFBRZGYX7tfqJMHgYAaVW6I2u27Ix/bcsLDN+K1hwK1QmH\n"
            + "IzpxaAAeSh6fOq7DDcm1ahEuxMZX/mV7SA8a8LQvYMk0KTeuexHw6B+hSipLUReK\n"
            + "bMIYSwYS2qMJLkI+TFP7nY4KvPGaKiIIbFDHMTRKH9jS2B+rUiVaDqCMZW7rZ8De\n"
            + "EGjGYTb0dnrT0ItmVRypQyi36PyUybAr39Ry7XDdQOJwdXOhq/qrL8IMQOhXgGAV\n"
            + "WD3VGVcJAaQHHgEM8nVENxtuDl62S71zn03EKo82x3F7MGnYfDaHFShb1UCRxIC2\n"
            + "SPrAAn8iH31smTl3CD+5HdEBv3xzeY+d/TKL2z1395SOMQNNEwWnJ2tyYwkueRdc\n"
            + "4O1EomIp9vm2gjZiV6nAnqaac87vdzOjGx2u0hLWfR+77tfL2P9q9BAd28yCTAie\n"
            + "i+OcgjBG0ooisI9qxAXRFMkgNJtEsoe0Fk37az3MBPOo9jWiPlKfGKn/n8/YcAHk\n"
            + "f5z30IiwK/BenYLJPFfWCdXW3OxXOECmPzKmt++iOHjpAeNiGJU8OBvjhHn8oGBx\n"
            + "ONb+XmvgNuzOkS6XtcPjt5bzbQBFFXnxiqbW5F9qPfgg28I397cQDI4ysGw460+e\n"
            + "hf7lSqfCFUhKENkkpPcUF2eSByni3VLLmdw5WscUk3Ey4kmiouvLk5opVdfJruyR\n"
            + "lbuZMTqThXRZMqdxicwEonZZaGzWBFm4MFFRm3oXJ9Nap+1QgIM6uqHVSBwR27rP\n"
            + "7ph5iP93E9L4lr78xUXPlbEq8sB2u/5luvS+jIu01Rjk1U+hIBLML6uOmNTHX8RU\n"
            + "AjyQas+bOQ3rhvik2bPaybLzWEhYuDpBaiOyn7aWtZHd5hRmZrobo3WcVBnnWv+p\n"
            + "bjn3bKluMhEtnXI4OtOP5TVAGUKP0k2eab5PRhHRvdzg7Zn4DZctA37w+pxwr/TC\n"
            + "hXAa2eyUnxhrxv8Hu9FrF8omCRyyW8s4Hmc+WVg16VXQl1bE0WKK1CtRUKQaiNCB\n"
            + "Ha6UYRczREGIFYwkY1RMAoQwwSuqeJG3yaPT7ezYSDqEZBAVr6j3RzgNsf0MMk/q\n"
            + "VDPOA6g/D99DIB6D9ghUFSgai/1Rvo5eaVs7B9X7c0+qK8H0zusYGDFd5fr9b+7W\n"
            + "9j0Zo54bGu4uAW+7vh7pq8jqOG+L3bMkth8b/7ZsLfkkYCtlqP2VfOL8qwWGzOFL\n"
            + "X6k9anNFgd5Ip52e5KvReNCHSKuHp7zrzk/WyVzU81ZLJYHCv4P3RHxStQHMdaqn\n"
            + "qxtPEXgX9ORWF2aw8mf9XbXarHrkHOkyhwi+tF7dLxVDPMREJKm1y/jqfSaJP1aP\n"
            + "0es4QSdF5CEBha7oixy00ejqGx5z3HoG6maIAOGUTb/aTQpPR8OmCzccP6rqERwS\n"
            + "6Sl+TznKi6nbbrjRcyDO/9TnM8G1Aj3T0fiU9h2hXJQnD3vuRwI5H8TkRDK4804C\n"
            + "MmzKH/pnAWl9UmOl/066Pz4g0XEX/jg8wPKHvnMyd6QbSud5Y1swOqcnperhhkVN\n"
            + "+mJqTkSujjFr7EMdkUsG1SK0BeTVS9lSb6iu7bLa2rOha9l/zPI1Fp7WiHqANnOW\n"
            + "xgcl3QJHVkvxqijDIrShYlS2bcn8xYL6e1PNxfJCqxEfDJHmkQwYDiqRZpkuMJ2Z\n"
            + "5+uYPCtX6+6bpIrmLBQZFxR/YgFLlF5t5rtHadL3DCjOWyvT0tOhvQfaoeOojgSa\n"
            + "rYrm5GzvClE0SF1PPsn/qsFY0s8fpjpVOwuU+E3qi59V6LVZB4NEYn8x8qTsdyeZ\n"
            + "+Z+d7LbnsPirvSFU+r/ZUCTP8Rzd2ejH8akGoUepeXgqUXHdqi86jvgoTds8vHUg\n"
            + "7E3OGjBH4my94VaNx6O8HIEhtY6zq2X18IkRvwUhO9dLIUZqYNAgC5n/8NQrxRqi\n"
            + "iY0RxJ9UObtef5YlNsNNoXmL4tXvJ9esMNTMFR5bHLlFW5dpfHd2TCzAZKxRPeGr\n"
            + "uKQ14KFmXfvcmw18tV7YXNTitPtBb+5osiJIX8GBG91eipxNytxK/qoVqvvfjytS\n"
            + "f4Bi0XC/I1E4xQ46UwTvGQKLTtRHyeg3vG+gX5raRK2Ny6IXDJj0scYE79q83TAc\n"
            + "uWXH6mJ0D04Edb/ut+2n5xL5VDde/rXlzntbCYTwxa4BbJmYjwQCiKVzDeknXdMj\n"
            + "xsV0Euw3Okm3CIQp7biPo7108y5keJll6HEpx7sWT37mNOoj4AFdm79wzEJQhl6p\n"
            + "KOo4Bpfj1etTFQAcU6E3weyVD9ROi7WtSBH4EFhFOfgfga1CHD8DHbwDdsa+dhIj\n"
            + "9mORCp7dEUPjt5Qi5mimlqQwYFfCHI+ap6VYsrhpzWr3gPi8EENRsbTUEWWezM/n\n"
            + "+BH4UnmFmQY7SGZyeHuDvFNzdNIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYNDxMc\n"
            + "IA==\n"
            + "-----END CERTIFICATE-----\n";

    // Self-signed certificate using ML-DSA-87
    private static final String CERT_WITH_MLDSA87 = "-----BEGIN CERTIFICATE-----\n"
            + "MIIdMzCCCwqgAwIBAgIUFZ/+byL9XMQsUk32/V4o0N44804wCwYJYIZIAWUDBAMT\n"
            + "MCIxDTALBgNVBAoTBElFVEYxETAPBgNVBAMTCExBTVBTIFdHMB4XDTIwMDIwMzA0\n"
            + "MzIxMFoXDTQwMDEyOTA0MzIxMFowIjENMAsGA1UEChMESUVURjERMA8GA1UEAxMI\n"
            + "TEFNUFMgV0cwggoyMAsGCWCGSAFlAwQDEwOCCiEAl5K87C8kMGhqgvzPPC9f9mXn\n"
            + "cderQbkCWM+n6Q7JcSSnOzI7m6Iatk12fEM/WlIe/+GPhuRqGIlSxEZ+BItynn/E\n"
            + "0RXn5I2hiW1f4RmxDc3e9iyzB5VAdLQjNuUoNt5h2pQfjTfqaKyBBvq+GQcGea9g\n"
            + "CFNxIPcHk7jqnMDm57e0yaXHQhxg8kRRuh6TPbGi7hbHlVnyGz0bgwWFCqQq+7E/\n"
            + "H01bn0g1+dh9/OsWLQ70p/3Ey6F0PNHIe7SWfaFsyHZLZWnfjuW9y//ppOBXSOb9\n"
            + "8iWvnk7rd3O2Lo+F+bVrVIlFVRhE+9iYBqSsNpvtLSVhAPaIpq1eCnCYJtxESeke\n"
            + "I8VQbmQjYe9aMTcS95vEsxhoYcqFpLqxfn+UPRuKMzqjrnzha0QNYBj54E2vVyXH\n"
            + "8ak/rRpaJ7Z4lb0kmqkWhd4grzLIt+Jox/lod9DIUAETWk8KjxuCZPpuvlo0nYrs\n"
            + "rRoWKZzPL9nHuFus4s7TqhJ2umHueO1+XKW2fN1FipNUAw5qu7q/VqCiMW/snbqD\n"
            + "tR1C/TFn8eD5CFXVxmUJshAmXcHlTsRLQ7p8+a7xGLRNgJEs51FmpmUeEWzr5JIp\n"
            + "pwYsCZMfcavSKT929+/DIVupeAADfljkcL27tDwbBDnq95xU2TtEqsnv6fvhUYdM\n"
            + "+ypky+4ozEwP53deXYcPHALlsuPFAEyZXyTJt3nLdTonfQ5x/UJetrwspWzhKdtR\n"
            + "9wdA8x5jl2tQxzEul5fXjFsawkpfo0fMkW4Kg/XDtnXNMLgeP6ELk0ROBzl1cczp\n"
            + "iyjaUduQVrxyjFsLEYHi+9OHtMeasaX+/s43Fnr3ct2tFOtMOYLaWlnQ6esXPsYx\n"
            + "UJEXACejq172qhKcuFhXJ7k1iihQHXE6cvPx2zFxQob5tkCAE68GBF11WS/At91H\n"
            + "xz7Zx1sR6dfGn3yt/DKAqQYsUnPEO+HDT4dEiGTOp7XJfW0y9ZvV8lOEZTu1xPqk\n"
            + "W+qLiUAoQ+ZFtrkmnivZiN2ssDMyj/sGBFD33wgAU+aWmyUeh17Owyz8WShA1pq2\n"
            + "mnXgazecU12VJmsIL08JyTFiszsNn3MHpOqqUhBEN/7Wb47j6rvUXWeyWoEz9JZG\n"
            + "i1K6/9v62T7vGpgYteQuxyJ4ij2NNSn8d30rpXCAHfrgHsiDAoN8H7ngNVcnZF7h\n"
            + "BGw/kV9q6C2tT7awNWpGUY/8g0FVw7T+ba+mzIpcz1PHOghJ2NRPfc9ydU5w4bff\n"
            + "tEe7TvSdGnGPYXG7ziAJUODOkmEGsVGj6HHVzklzG9ZlCpsMqXLaHF8TbUSCDqY4\n"
            + "PAjzs4TPIzjnicUT9hjMVpSm8M7hBFEeHtfF8joev9ig24QkVTJAFW2/YigxsMZD\n"
            + "0cVRtvP3qY0puFwt4Fpl+mFe7hZJW9kHN2chFbU+kcXZACjPPxqTlToVPeU7RAhO\n"
            + "nM/2tzZpOSba7+uy13qlrWibkvMWhmad8W0XFcxY96LPty3RpR6S+CWZOnQCK+fp\n"
            + "62BUZURXCU0Uko8gIV57IirFa1GtvsjYvbaYOXmn46IbRLXRUYypfQtRlfUe1qJD\n"
            + "UMiXR+Ht6lG0SOPpFHBUzpJ4c8kNs5TYaIjgff8XdZPW954VIwIgSusDviOGrz4k\n"
            + "B4vQKLFon14UfJ9FLIzrAuxZzJ22OgNXbO6v6YI5AjiX2gI2YwpTwN5/Q1oZhpeS\n"
            + "+rNue55jV2DwkGnmQy5wADWsKgKHn/8KHhvsUiBHGT2U613x79U+6hFEyniUCFL1\n"
            + "7JcnkEs2bt5PXi0zH61fwoLqLEfpIxQnccPddahzV0h975nl8Y6dntYjwXXQKIjF\n"
            + "H4LAeoDVRxazw8K9vi6fCpu6rr601Sk2h2QG9cAOjku9Cl7AV5fmIHxatsiPGmiE\n"
            + "Ib0FoRT0194qwkH6Dovt/0f3Yt3L6qkQBPjTHoUJXIEFSZStOCbjRLqWBAgQ/Asq\n"
            + "0d5Iz63gAsYuWkmgcxqzg0S8FjbfFr9gfVaFXlbWhAA8cY5LrZ5aCZl5/N3uscSn\n"
            + "d2zTejQXyw4YTinvm8DodHW6ZjvgngCrVi63wPcWX5aam0JBQZjM8b/yosjWiaQU\n"
            + "7OdmKSdmVonpTblh667FYVy8GniVxoUayWFDL/ERjUYH0y753HMtUTM75LTQ4w3e\n"
            + "p4TsqL5H50G+nBljHcRwpS703BOk82M/1DTXh8Fwl3tBffWY4dDd5Qa7cdbwvBfs\n"
            + "cOOwPNwZZcs2mT9jOwRy5Q0JI6xsZv3x0+ZFnMEh8PX5TQnp289daQ4jIzg4oLrL\n"
            + "fGONGyZQpDCM0XG2hVEm0dpnKm7YWo14wob7VvSrPSFJdSgEXGMmLIpCry+YAsU7\n"
            + "e7i+KOeP4LXORfu3oa8aOyio2Ut4kOPIguObyY6fCtdgJb8N0vACmOcUGiJrPXzu\n"
            + "QU9gTR4LpU0R1f5YvM6mrXetLowcqs8yRZAUt7kQAbHvqK0XKlI/uONltXcSG/n9\n"
            + "iKLGDCHoIde2rLR6WpleQMrO1cIjuP5t5eGOnS5Yk67+u3quf/GhRiYOLxEOk5Uo\n"
            + "IToAJaOOx5qryGGyXrxQmkZ0wTKqrLfgFG8U79Ec/K9Mqk93WnFs4yXgpDWk00nX\n"
            + "ILzxN0UK/EUEb8Gh+DqdMpd3pwhOSq2ucSLOlwBZMFKOs8f38RKbNyiHo3EVWjui\n"
            + "AaJcvx3LZOfN7gksMUH7VVD+PQ3YLocOV4srRlAIGBE7j2Vpdzxnc4W2mkK3fcun\n"
            + "rP/ZX9RFLiOqodN+HaIVHqZY1Ao1lrJ6yfgSncbPBkN3JiS1n09GEjDfRxyiYIfD\n"
            + "lC1cZoffYIKDWTWj+Hy3YrDDsdDdpKZTOWW+8be4KS4lTAFNCQ/thXxEwYOcaUwK\n"
            + "ZOP62QoR9TRyK27hV08uFJ1V10TeSIcCTghRFDHAYnUOFsdKufMkLy2z/7EqjWEH\n"
            + "+qIp1vY3OwfzbTkys72wTBndZOrdf5PDxWTDWKHIHc8cnDHlsGVo+XVEwX3BVpjF\n"
            + "yziYOpr8Qng/qnc6UsnYJgaQvp4xVqpbwVCd6j9pWHaVzW/xcrqD5qbYp9a767vN\n"
            + "o2cnMZg/ibxYMdw3w/PFxW+sxpfzyyC9Xbrb1wLlSESsL2JpAf4Vnbk9/Udz2P5z\n"
            + "ViuEbB/IVtGAJ2KEDrxy15iL3nXLynDTGdMs4MwCU7sq1FVyPuDH9HNs5uZmXFrK\n"
            + "MqSBxTg5vCWRZ7AT0EIzle65qq7jIGFJp9VQ1n/F/f5Kilw10lELZkN5q49yhVoq\n"
            + "9Hq84qYyBI6vieXLSojevFOllRA6zOTxz/GKz/B6/h61cWqh5AtjE0w6OulXn6h/\n"
            + "UVvgk8LSnbbWtlyTZh4AY2tZJwTQk8xnFsI0LrGFPUjIXGOsiihURix7d+fjvR6s\n"
            + "W8oo/6oAtdNJ+KVHrYdblqjCspEMkwEwmj+ROKVpMRH1WzwAnKlHw538gtmOscqk\n"
            + "qcvohfeG+oblW+BiIi+LqQqXQHMyazEhKuzgo0pgo0IwQDAOBgNVHQ8BAf8EBAMC\n"
            + "AYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUiYhnULV8JNs/wBLmHt5ZdTM3\n"
            + "N08wCwYJYIZIAWUDBAMTA4ISFAAIeD1WXvx7l0QPi9mBi0Zr5TjbzO2xNkR9J6d4\n"
            + "3J98fPMtFHVbMPEwhJjZizrOPmedfxNYjxX4PYY9TruXu4HDyatYvtuR87PSAHVt\n"
            + "kxXs9T6wDRgeBJDsBw5lsxDAo6W+F6dv2kxmx2hs4ik0JF93wSeygXg0uUgSF8SA\n"
            + "w6B7hE/ZvPUteNt674Mc2zqOyOAYWM6dWjDJMtKmfdLk2vA1ph0BubRHI9MHGzil\n"
            + "qUj7SkA31jdMX2a/ARe5b/fbWiFtjIjk/AGEqnJqZLR23DBqDolg0vS75lYUGBpR\n"
            + "/33bwU5HCHr3hIO7LwVhJOzxki+2hBOApsR61lh/81UPnGFNIopvVtNa7n8Za6ri\n"
            + "vIHEVcf48CsSJSN4mdVPkRx3CbtvPC2BXUhu83TE2iBwmdwfz/P1WefFL1rGCkQw\n"
            + "E0GYKgp+YoCQipTISdFrNvCYUKgWbTh6aT1dpFi2j93iPhIr857jdrXrBQ3R/K+i\n"
            + "KisjM3U9YKiZKrtiAiCSruWJ+bB4HArinzITmfqwNpX4TzgpwoF5B3nxfRzVonee\n"
            + "bQVNpxZk/JLWGQwwybcfZHsTRb6awtP7xvWtGu0auCG0f0DBIW6WPzvQ9TyO3ur4\n"
            + "IyvLvz0j/L8CjIRvaEq8M+s5ROIGEs6yYHikv3YR5gBAt63y4+rmL+/b4M4KMELU\n"
            + "4sFtIcwhQ8nVxDX9UjZaBr5mqX4AC4AP423FAO14RQVUdWS6qvHUMRvI/9afQtak\n"
            + "Qp7Z4j86AkDWPObDiSsAa9rJjLlc5kBXmijtHLHvMK8WGz2tl8S9pYhbqUjS7mMN\n"
            + "yJBUq1NErT6pDEgWFfh8FDUxmZ6Sw2sjSt9giOaPfAPOTI7qgKATCyQ9Dj31/VbT\n"
            + "5vTasSPJLeaf0iK591k/ARkc/YRv+w25A5gR6MpC2N8gMmnDFNf0x7nXwC4o0pqR\n"
            + "jDNuJlTGnVLzz9kOEhZs9VNrBn+f1pQS6fLm4YH1SH3He+NIFhs/H9wdIAwtE6iR\n"
            + "xDrb5J5FH5IaR6sWUv2ifKUsjFJI4ziifezeYJQJlgcNBnMjUH1vH0soWRGZerAq\n"
            + "ZWwfnzt8n7BD+BGIP+88BftaFwPOVndu5vKbY9R+efPMwoN9VFKSxCtCAk/Y4eiM\n"
            + "7QwNIQMMCbwfo794DMwYWGxat9Jql8JzSMFYH5rusNdtqs63fkm5m8SczmKq3xuW\n"
            + "D+Gd7ilJA69xJUte2EMhiEty2Z1XBVE944cXeZWwPrwMuuokaa7YOZw/DqObVfcU\n"
            + "hnTKj5cS3pARFNnJU9Nr7lJrtThgT6tETGaQEACYm+QWK0z0B3sJisyfXwz76q9Z\n"
            + "aX+Z/a6i8AUGBA6GTy8K1aCfawNu5Xdn8iV/qVHhgNP5XX6G3f61RDr8zUY9+Xa3\n"
            + "OCDRsUnw3zhunja9H5UiFQRQa2tzz7T7WW2Bl1R+mQrI3ZsDrNFCh9axwCe2ge4H\n"
            + "iQx9D6uf6ldqmEHZYMm3ZdUYYRZ2TsBBjYhzU2y70MO1CAkMXIPxJUaIbE0lrt0d\n"
            + "qwmfRr2r4ZuDW+lB0ptXweDrHXQdJf7SHri+n9xK1PH1keemtotpv7ctBzFB6tWe\n"
            + "MOJIN7tiVaX3V4YZEvfR19L1vSRkFKoVEYDu0BOagJYAdX6rS+hrlWgoI92/yZ4X\n"
            + "dd8lRTAGiC4nc/A+THYT2BcRYSCVIKJjrtdQd1zijq/j93Hs8GWWyx70vx65cfpU\n"
            + "6BsXiakzrQ8PZpDVBq/d4Nd6rslm3oLr17S8PlsQIN/f1rKNJGhP+08sc4Bfs8Pa\n"
            + "ZiqnICuEZsxGrfgbvcJwO8jTTblfUORj0U7VQyvDr9bejy4TpfoB3g+JG8s4d8GQ\n"
            + "DFBSuxqt42E3CYMqPdpzmUyF485u1UzPMYPB++hhYn4zR14Azf+8RWqaOYQu8L3+\n"
            + "auZWn9SzlaWd19WZGPVnjkD/2pHF5G6Pfu0RU3x2Bw+NbCFzEzw6mDn9WZiag8mA\n"
            + "90gU236/Vv6PKRqXqegczB/KBJwc3Ebs/gUJfv4yKUlcxcquKgYxfIFiYgCgqzVo\n"
            + "NYp79pKINC3l6Gf4ARGnjsjxKHApKe7RqGafZlPQjevLY3q0KT82x/l73Ypw88RV\n"
            + "jiTfoq/Dq2x+yXY30LYXY1H0X7Bso32t4T7rJxXsj5Rca/2XdiWGw7Gsunkq+VXl\n"
            + "k0i3GytZSmCMZ7n4kijyxGrMuNDO3+CQuQh3byLtwQ39NmR7AXdsmlCJ9QA/rb7S\n"
            + "gOrcTLbcpYE//xFTsMhwOxWIDYp7OPBYzB/Fv1xFDn3otyHHrWMq2+uwLFhku6nz\n"
            + "poWELCBoebvLhNANy3/pu/IGl5LTjRL/cYDAE0BtOB18Uf0Gyb4wjFC0crxJBZ0R\n"
            + "apK+BpDvFKtD0cIMdt7fdv/nnjo0bYm484Q6h9h4fAnVnFn0zd9Fx6sZQvxzjA/p\n"
            + "ztD8W1WX4ygVcojTBe4ToFRVjpEYTMaIIm46uh1HRZIR/G3eoaKCPRH+Ic+XAD6y\n"
            + "YfEV8n/YY9fBm4Gm8SC4RgvumvIXbF7sr3dbhVjm4DqW1NWcVLeavv5yI0vyDCiq\n"
            + "FsVUUzvfBNiROMwttD804e/zZSjj0w+ssoI/viPnGgg1f8ewHdGqNavX5TM1V+M9\n"
            + "AzKcvDrHAS4MaZ2yVQXDyhmKSycNG55hx3gtSu+tBr/73TC8AxY77Jm0OYQCibLi\n"
            + "bsEG2rSfyAVK90uOEWC6Si9bmS3iCskVPWWw/W31uMXfpeYsXcF0qX3JTr6uTyfx\n"
            + "AcJRXxsQAh/uwYLVRQIZjmxsAmVJiD3oUxTgHyxnGXJP2H26E8toIMVGRbK4rYzi\n"
            + "0U7PODhTgP137Rz5h68Ks5sKtIBtVYkMyZ2eFSg1GjPt0aQ4ET0q8cakrgwZqH0s\n"
            + "04E2zzLfJotOLnHaiX/i/hw7zb6HtNTSz5EirsbeoBtsbs5KReXWP6DlvrlhLTKJ\n"
            + "7R1VFe/4P1EhZipOHqacV3pY+aLU2G9L1aym22HEsp8vUnjg2wS0EQ8mYrU2jyGq\n"
            + "lXyCLwoDA+yfVv6QMPMC0WssS/Yh7ZGrOTZFuPnHkHxA7OVByKD/NM78uBO/GHsn\n"
            + "CvD+Q0ZpS+SxpGv4Bt90T6pIjZ1xEunFQeJzFrm75+8NFa/gb+gh5LXxQBJO4hXa\n"
            + "XOmhHYZb+DAXzfq2tAFOMfnaKTB43ffFElTi2pXxmlCNAdyPhGsWUtTeV6clHmOT\n"
            + "JA7RQwPjlfsYgHk0Xg+4U/h2zB7bQpDiaEzDUxHoYCxxpXvTpsmoBFkXJ7409vq3\n"
            + "I/SKGW/rxvD5s080T9lwZ5Cj5j0amJy8/fMPjrcfywJGNa3sVo/p05oZTIzS+79q\n"
            + "ExOQ3DEenFOBtVQkZrPGCo7rYh5uZTuLUv1d0/jQ8/4/DqlIsMeGLeJeBkwpRzWf\n"
            + "olvVijXlzjNndkbQh0FQtyUi7GJB0Z0G2wOAzQ6ovndufPfKDRvVnFWE/s4NuE0a\n"
            + "dnoWICnWguQGN9fDeMhHrhheLW3/5OFdVbr9DTX8jX/1b+X6fLwu4YM3GE3GL15Q\n"
            + "3sXNqQYp1sgan+2rJXkBnNSd12v5l/VDvCNZQacBB5Jf8JUVPsYQdyxf1STIDCKN\n"
            + "gOeB6GTildIMaJb1Aoh7GO0jB+jurqVuJkljk0llL1CVKOS4DqR316akU4B7JjYb\n"
            + "HspvzsTgbFBBZnQsEvikSjWf7ycn009HIB91pwVWKbKDl+V15Myd45rcCPQkELUj\n"
            + "L48ue4b98+HrvnNLesuknTCKYVHBNS3i4gsf7QYNXm+1jW8jsoR9xTtnUZuS26YE\n"
            + "5EjzmQVw8JvWX2hVRaAkYs0kxy8veYnL6HsMUtpS7qF3Cq7PfVaNCxvxrtPKj1jz\n"
            + "MimeORtEE7bG/roR1DJiF3oqRGzlr8WcSCiHgc+RZ/5aG/QmKcbQlMZTer3qWvS0\n"
            + "o6fx6KPoz/ECbd78KbrjnnUkk2SpU+xSIxu1gTqAs68l78pDgAp0xGZGMvbcGJzC\n"
            + "zZVHi1lPxXjqOhWEDpKCK3FmyGEdRkry6NG6pbyvHBZJWJp+sWuIm1Tgt87QuiWl\n"
            + "HjT00PFS++aeH0NoLYGl3gX4liixte8QAyfktPs6AjhXYrSrHnIdp/9hczxB1wce\n"
            + "gZ7ETAMxFHQzDpemwCSNHdmUGf64OYDyQiqefJBlRpxBA9dr23uFJMTiGRQJX+Je\n"
            + "6hcdiNzifZb3ZJpxfZQVugUTi2ompoX7do91VkiE+jjMm63ha5TbYtH52jzilPPp\n"
            + "FzAYVWdqfuez93vQfPuLU94wCCu6zfNPGeHbWq/3oxiO9AjGqckGtCtBGTAD0nOl\n"
            + "ppsMpYRLu8uMeBIzCqP5PhVbhoH57fui3bsBHK6TPnKzTREX0m1mWxlTItymNCm9\n"
            + "5Bg8AiVczwxZWHPSXExz2zB9MWXiwL4KYBbIeFpOg9WB7D6w9Z7Xo4Mj2Xcv3zaB\n"
            + "iu07SFw4ID+xsBn74K2pCZVDKR8Qb20tBXjFNzTRAZOJRShM5omjWz/5P+LUDgfj\n"
            + "ExDlXSHAnL0NtEpk6j8W7S3cJD711uXOtLCoHcBWSrIenYHLwWxWg7rdkRJdi01V\n"
            + "HzCRviEV6hIbIUOAM3hsW3a/yMDgch0PvXCQVB07246ZywKaE14u0fbEkFcuYl68\n"
            + "6Dx/oC3yHRaw+5PbgDz2Xr+xOAsbpYRxe2y2X+Yjats2E9SisEQyVN7IPJZ5rYTi\n"
            + "YJzUdfLZy5igb9/cxzqIvg+seMakLjUbaYvcMRclaN6uwglk1bxSlhLVgLoKe7y0\n"
            + "Jb/+G/PvGkDrdQTQRrohPgCgcU0RlQ6UsOJJ4+5uC2zbTqMrQCQBGmjlEWChM7Jf\n"
            + "mQNCcyVZFqkuo6lPsrz6/MCi6encL4wxld0O58cEuLzV2JYPK9IWD3/TBMEH0ns7\n"
            + "CYT1DeuBOkZ7Bz5jRxSaHPS1MyKJ1jXV0jwnMLMDaKXOPM66YVU0fw3yH2EQRFBb\n"
            + "zjgGvY7bqGMkY3xqkhCDC2NmAqg1J7Qe7mDy0t9MfGpXHuhRSEike+sKcgP45Lke\n"
            + "T6Z+owIv6dn5QUiEAW5m/khTYWfhLw3FUOgBAEwRqGxbeY4mypsfJYQWJK0jJxN5\n"
            + "CN0jul9l7rEHuL8eT0UhjkTxXnXa6N+eeL7fXmXLEiePFSTUWXwDfUCqEiKtUUBG\n"
            + "OT1ffil1nmEIe/Hx05B9LStvIbuKGnCYxTOol8vLiJG1ahvGWrhiW6tm824q/G6w\n"
            + "hM2yFZvlQ35cQ3pzjvgK2p6x0IsXPSKjpuTq5rKbMpqTwtxrR5k2Bufs/0BDGDHo\n"
            + "OqfGSgnn6ykbGp9nHBT/hRclGwQZtRcJW5f9cBCsWQY742UtJ0FCYuzcL5uRqKRv\n"
            + "pYO7RYg2XElC3YJDJo/J9fozQ8vhf8NTnSQ0HVguCkY1OUEueTUH5L5Ifr+cx+Jk\n"
            + "dr9eaO7JnmKA/urs8Ffy02AAiQ2rULt/hZsgmFfWeDDgama1Ncp2O6yXm57tMeK5\n"
            + "swlatkq5YcV/amZgyxcq7es9hbyb87n6j8RnPeKBPROO+F4NRW5QHlnbreda3Tas\n"
            + "8Ze69HL2NR8j54AhTbxpR6q7Zz4DPWGqYfmocoX4r7xb+HnJG+qWkvqTP3AQEW8C\n"
            + "izLeOXEANQ9YCOF2GmHwg2Gi3Iw88PqvERz0T9/RCI5CiGa+Oli19jjFx2L7J5Ct\n"
            + "6RS+DPYStrO97GuIrM9tGz14xBDAWuURfKECXTLMA6AW8zAjYBjWV5zQuZMLMXou\n"
            + "yqK0FJG4JqfSWSJv+DvDvGdmCkxcBiDzO6wDGWpFF65F8z7wHKU7VMzJa3LWjlfO\n"
            + "lIn7fepvuNyI+PK9UyvX0am7R29bxNyCTNJHQuVJv93WrokJX7IHOaZXyY7T4bMj\n"
            + "yw0yMsWOanzDyh0y7OGhDgXiJS42y2XU0UH/JGGEZbZlEpfNNNOPYcYvMfuOlwww\n"
            + "ZTIl7tStk6k0AtZ77tHmw2iu5730yoXlTrKxe72lAdDQlvXLTkdXXw+oxg+O078n\n"
            + "Zt5jdDQgFMXYxyqanZgc5scGn3X4Q/uXgZ0QSlhPErGjtIC5/XdAUraYJZNo6lu3\n"
            + "r2dYCUIfo6xun+6+QnoT7OXpb+hc04Ky4QYHq5EYd60H50ogBiHTzC2QLcqDbpK4\n"
            + "rnVLSDqKkbgKCwwRPEiw8SU8WZu5zwG9ygURLGN4obLeSQU8UHyCteEbbpGrstXp\n"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMEhUdHiUs\n"
            + "-----END CERTIFICATE-----\n";

    /*
     This certificate is a modified version of the above self-signed cert. The cert has
     been modified to change the certificate data's signature algorithm
     declaration from sha256withRSAEncryption to sha512withRSAEncryption.  This causes
     the signature block's algorithm (which is unmodified) to not match the cert info.
     */
    private static final String MISMATCHED_ALGORITHM_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIFMjCCAxqgAwIBAgIJAL0mG5fOeJ7xMA0GCSqGSIb3DQEBDQUAMC0xCzAJBgNV\n"
            + "BAYTAkdCMQ8wDQYDVQQHDAZMb25kb24xDTALBgNVBAoMBFRlc3QwIBcNMTgwOTE3\n"
            + "MTIxNzU3WhgPMjExODA4MjQxMjE3NTdaMC0xCzAJBgNVBAYTAkdCMQ8wDQYDVQQH\n"
            + "DAZMb25kb24xDTALBgNVBAoMBFRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\n"
            + "ggIKAoICAQDCMhBrRAGGw+n2GdctBr/cEK4FZA6ajiHjihgpCHoSBdyL4R2jGKLS\n"
            + "g0WgaMXa1HpkKN7LcIySosEBPlmcRkr1RqbEvQStOSvoFCXYvtx3alM6HTbXMcDR\n"
            + "mqoKoABP6LXsPSoMWIgqMtP2X9EOppzHVIK1yFYFfbIlvYUV2Ka+MuMe0Vh5wvD1\n"
            + "4GanPb+cWSKgdRSVQovCCMY3yWtZKVEaxRpCsk/mYYIFWz0tcgMjIKwDx1XXgiAV\n"
            + "nU6NK43xbaw3XhtnaD/pv9lhTTbNrlcln9LjTD097BaK4R+1AEPHnpfxA9Ui3upn\n"
            + "kbsNUdGdOB0ksZi/vd7lh833YgquQUIAhYrbfvq/HFCpVV1gljzlS3sqULYpLE//\n"
            + "i3OsuL2mE+CYIJGpIi2GeJJWXciNMTJDOqTn+fRDtVb4RPp4Y70DJirp7XzaBi3q\n"
            + "H0edANCzPSRCDbZsOhzIXhXshldiXVRX666DDlbMQgLTEnNKrkwv6DmU8o15XQsb\n"
            + "8k1Os2YwXmkEOxUQ7AJZXVTZSf6UK9Znmdq1ZrHjybMfRUkHVxJcnKvrxfryralv\n"
            + "gzfvu+D6HuxrCo3Ojqa+nDgIbxKEBtdrcsMhq1jWPFhjwo1fSadAkKOfdCAuXJRD\n"
            + "THg3b4Sf+W7Cpc570YHrIpBf7WFl2XsPcEM0mJZ5+yATASCubNozQwIDAQABo1Mw\n"
            + "UTAdBgNVHQ4EFgQUES0hupZSqY21JOba10QyZuxm91EwHwYDVR0jBBgwFoAUES0h\n"
            + "upZSqY21JOba10QyZuxm91EwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\n"
            + "AAOCAgEABTN5S30ng/RMpBweDm2N561PdpaCdiRXtAFCRVWR2mkDYC/Xj9Vqe6be\n"
            + "PyM7L/5OKYVjzF1yJu67z/dx+ja5o+41g17jdqla7hyPx+9B4uRyDh+1KJTa+duj\n"
            + "mw/aA1LCr6O6W4WizDOsChJ6FaB2Y1+GlFnKWb5nUdhVJqXQE1WOX9dZnw8Y4Npd\n"
            + "VmAsjWot0BZorJrt3fwfcv3QfA896twkbo7Llv/8qzg4sXZXZ4ZtgAOqnPngiSn+\n"
            + "JT/vYCXZ406VvAFpFqMcVz2dO/VGuL8lGIMHRKNyafrsV81EzH1W/XmRWOgvgj6r\n"
            + "yQI63ln/AMY72HQ97xLkE1xKunGz6bK5Ug5+O43Uftc4Mb6MUgzo+ZqEQ3Ob+cAV\n"
            + "cvjmtwDaPO/O39O5Xq0tLTlkn2/cKf4OQ6S++GDxzyRVHh5JXgP4j9+jfZY57Woy\n"
            + "R1bE7N50JjY4cDermBJKdlBIjL7UPhqmLyaG7V0hBitFlgGBUCcJtJOV0xYd5aF3\n"
            + "pxNkvMXhBmh95fjxJ0cJjpO7tN1RAwtMMNgsl7OUbuVRQCHOPW5DgP5qY21jDeRn\n"
            + "BY82382l+9QzykmJLI5MZnmj4BA9uIDCwMtoTTvP++SsvhUAbuvh7MOOUQL0EY4m\n"
            + "KStYq7X9PKseN+PvmfeoffIKc5R/Ha39oi7cGMVHCr8aiEhsf94=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This cert has an EC key with curve prime256v1 encoded using explicit params.
     */
    private static final String EC_EXPLICIT_KEY_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIICAjCCAagCCQCrIzClvU58azAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARUZXN0\n"
            + "MB4XDTE4MTAwMjEyNDQzMloXDTE4MTEwMTEyNDQzMlowDzENMAsGA1UEAwwEVGVz\n"
            + "dDCCAUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAA\n"
            + "AAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP//\n"
            + "/////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDE\n"
            + "nTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPSh\n"
            + "OUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAA\n"
            + "AP//////////vOb6racXnoTzucrC/GMlUQIBAQNCAAQXU+GFdLabcY/RvzoNjLhC\n"
            + "6uN1Yt1baN2NYyKYEhwR9nb8nLa/m7f30OOi/8OrxQhnUl5qW0I0IbHflGnsqQ6s\n"
            + "MAoGCCqGSM49BAMCA0gAMEUCIQDRXoZwmnsIJfg4mTemkM+heMS1iXRYUO0Dar5u\n"
            + "Qhy0YgIgYWr0qSCLqxUQv3oQHMUpSmfHtP0Pwvb3DbbH6lY7TkI=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This cert is signed with OID 1.2.840.113554.4.1.72585.2 instead of a
     * standard one.
     */
    private static final String UNKNOWN_SIGNATURE_OID = "-----BEGIN CERTIFICATE-----\n"
            + "MIIB2TCCAXugAwIBAgIJANlMBNpJfb/rMA4GDCqGSIb3EgQBhLcJAjBFMQswCQYD\n"
            + "VQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQg\n"
            + "V2lkZ2l0cyBQdHkgTHRkMB4XDTE0MDQyMzIzMjE1N1oXDTE0MDUyMzIzMjE1N1ow\n"
            + "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
            + "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
            + "BOYraeK/ZZ+Xvi8eDZSKTNWXa7epHg1G+92pqR6d3LpaAefWl6gKGPnDxKMeVuJ8\n"
            + "g0jbFhoc9R1+8ZQtS89yIsGjUDBOMB0GA1UdDgQWBBSrhNKsq5Xwgk4WeAdVV1/k\n"
            + "Jo2C0TAfBgNVHSMEGDAWgBSrhNKsq5Xwgk4WeAdVV1/kJo2C0TAMBgNVHRMEBTAD\n"
            + "AQH/MA4GDCqGSIb3EgQBhLcJAgNIADBFAiEA8qA1XlE6NsOCeZvuJ1CFjnAGdJVX\n"
            + "0il0APS+FYddxAcCIHweeRRqIYPwenRoeV8UmZpotPHLnhVe5h8yUmFedckU\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This cert is signed using MD5, which is no longer supported by BoringSSL.
     */
    private static final String MD5_SIGNATURE = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDJzCCApCgAwIBAgIBATANBgkqhkiG9w0BAQQFADCBzjELMAkGA1UEBhMCWkEx\n"
            + "FTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYD\n"
            + "VQQKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlv\n"
            + "biBTZXJ2aWNlcyBEaXZpc2lvbjEhMB8GA1UEAxMYVGhhd3RlIFByZW1pdW0gU2Vy\n"
            + "dmVyIENBMSgwJgYJKoZIhvcNAQkBFhlwcmVtaXVtLXNlcnZlckB0aGF3dGUuY29t\n"
            + "MB4XDTk2MDgwMTAwMDAwMFoXDTIwMTIzMTIzNTk1OVowgc4xCzAJBgNVBAYTAlpB\n"
            + "MRUwEwYDVQQIEwxXZXN0ZXJuIENhcGUxEjAQBgNVBAcTCUNhcGUgVG93bjEdMBsG\n"
            + "A1UEChMUVGhhd3RlIENvbnN1bHRpbmcgY2MxKDAmBgNVBAsTH0NlcnRpZmljYXRp\n"
            + "b24gU2VydmljZXMgRGl2aXNpb24xITAfBgNVBAMTGFRoYXd0ZSBQcmVtaXVtIFNl\n"
            + "cnZlciBDQTEoMCYGCSqGSIb3DQEJARYZcHJlbWl1bS1zZXJ2ZXJAdGhhd3RlLmNv\n"
            + "bTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0jY2aovXwlue2oFBYo847kkE\n"
            + "VdbQ7xwblRZH7xhINTpS9CtqBo87L+pW46+GjZ4X9560ZXUCTe/LCaIhUdib0GfQ\n"
            + "ug2SBhRz1JPLlyoAnFxODLz6FVL88kRu2hFKbgifLy3j+ao6hnO2RlNYyIkFvYMR\n"
            + "uHM/qgeN9EJN50CdHDcCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG\n"
            + "9w0BAQQFAAOBgQAmSCwWwlj66BZ0DKqqX1Q/8tfJeGBeXm43YyJ3Nn6yF8Q0ufUI\n"
            + "hfzJATj/Tb7yFkJD57taRvvBxhEf8UqwKEbJw8RCfbz6q1lu1bdRiBHjpIUZa4JM\n"
            + "pAwSremkrj/xw0llmozFyD4lt5SZu5IycQfwhl7tUCemDaYj+bvLpgcUQg==\n"
            + "-----END CERTIFICATE-----";

    /**
     * This is an X.509v1 certificatea, so most fields are missing. It exists to test accessors
     * correctly handle the lack of fields. It was constructed by hand, so the signature itself is
     * invalid.
     */
    private static final String X509V1_CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBGjCBwgIJANlMBNpJfb/rMAkGByqGSM49BAEwFjEUMBIGA1UEAwwLVGVzdCBJ\n"
            + "c3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUwEwYDVQQD\n"
            + "DAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATmK2niv2Wf\n"
            + "l74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUd\n"
            + "fvGULUvPciLBMAkGByqGSM49BAEDSAAwRQIhAPKgNV5ROjbDgnmb7idQhY5wBnSV\n"
            + "V9IpdAD0vhWHXcQHAiB8HnkUaiGD8Hp0aHlfFJmaaLTxy54VXuYfMlJhXnXJFA==\n"
            + "-----END CERTIFICATE-----\n";

    /*
     * This is a certificate with many extensions filled it. It exists to test accessors correctly
     * report fields. It was constructed by hand, so the signature itself is invalid. Add more
     * fields as necessary with https://github.com/google/der-ascii.
     */
    private static final String MANY_EXTENSIONS = "-----BEGIN CERTIFICATE-----\n"
            + "MIIEADCCAuigAwIBAgIJALW2IrlaBKUhMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV\n"
            + "BAMMC1Rlc3QgSXNzdWVyMB4XDTE2MDcwOTA0MzgwOVoXDTE2MDgwODA0MzgwOVow\n"
            + "FzEVMBMGA1UEAwwMVGVzdCBTdWJqZWN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n"
            + "MIIBCgKCAQEAugvahBkSAUF1fC49vb1bvlPrcl80kop1iLpiuYoz4Qptwy57+EWs\n"
            + "sZBcHprZ5BkWf6PeGZ7F5AX1PyJbGHZLqvMCvViP6pd4MFox/igESISEHEixoiXC\n"
            + "zepBrhtp5UQSjHD4D4hKtgdMgVxX+LRtwgW3mnu/vBu7rzpr/DS8io99p3lqZ1Ak\n"
            + "y+aNlcMj6MYy8U+YFEevb/V0lRY9oqwmW7BHnXikm/vi6sjIS350U8zb/mRzYeIs\n"
            + "2R65LUduTL50+UMgat9ocewI2dv8aO9Dph+8NdGtg8LFYyTTHcUxJoMr1PTOgnmE\n"
            + "T19WJH4PrFwk7ZE1QJQQ1L4iKmPeQistuQIDAQABgQIEoIICA1CjggFGMIIBQjAP\n"
            + "BgNVHRMECDAGAQH/AgEKMCEGA1UdJQQaMBgGCCsGAQUFBwMBBgwqhkiG9xIEAYS3\n"
            + "CQIwfwYDVR0RBHgwdoETc3ViamVjdEBleGFtcGxlLmNvbYITc3ViamVjdC5leGFt\n"
            + "cGxlLmNvbaQZMBcxFTATBgNVBAMMDFRlc3QgU3ViamVjdIYbaHR0cHM6Ly9leGFt\n"
            + "cGxlLmNvbS9zdWJqZWN0hwR/AAABiAwqhkiG9xIEAYS3CQIwewYDVR0SBHQwcoES\n"
            + "aXNzdWVyQGV4YW1wbGUuY29tghJpc3N1ZXIuZXhhbXBsZS5jb22kGDAWMRQwEgYD\n"
            + "VQQDDAtUZXN0IElzc3VlcoYaaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXKHBH8A\n"
            + "AAGIDCqGSIb3EgQBhLcJAjAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQAD\n"
            + "ggEBAD7Jg68SArYWlcoHfZAB90Pmyrt5H6D8LRi+W2Ri1fBNxREELnezWJ2scjl4\n"
            + "UMcsKYp4Pi950gVN+62IgrImcCNvtb5I1Cfy/MNNur9ffas6X334D0hYVIQTePyF\n"
            + "k3umI+2mJQrtZZyMPIKSY/sYGQHhGGX6wGK+GO/og0PQk/Vu6D+GU2XRnDV0YZg1\n"
            + "lsAsHd21XryK6fDmNkEMwbIWrts4xc7scRrGHWy+iMf6/7p/Ak/SIicM4XSwmlQ8\n"
            + "pPxAZPr+E2LoVd9pMpWUwpW2UbtO5wsGTrY5sO45tFNN/y+jtUheB1C2ijObG/tX\n"
            + "ELaiyCdM+S/waeuv0MXtI4xnn1A=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This is a certificate whose basicConstraints extension marks it as a CA, with no pathlen
     * constraint.
     */
    private static final String BASIC_CONSTRAINTS_NO_PATHLEN = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBMzCB2qADAgECAgkA2UwE2kl9v+swCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL\n"
            + "VGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUw\n"
            + "EwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATm\n"
            + "K2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI\n"
            + "2xYaHPUdfvGULUvPciLBoxAwDjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0gA\n"
            + "MEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGohg/B6\n"
            + "dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This is a certificate whose basicConstraints extension marks it as a CA with a pathlen
     * constraint of zero.
     */
    private static final String BASIC_CONSTRAINTS_PATHLEN_0 = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBNjCB3aADAgECAgkA2UwE2kl9v+swCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL\n"
            + "VGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUw\n"
            + "EwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATm\n"
            + "K2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI\n"
            + "2xYaHPUdfvGULUvPciLBoxMwETAPBgNVHRMECDAGAQH/AgEAMAoGCCqGSM49BAMC\n"
            + "A0gAMEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGoh\n"
            + "g/B6dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This is a certificate whose basicConstraints extension marks it as a leaf certificate.
     */
    private static final String BASIC_CONSTRAINTS_LEAF = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBMDCB16ADAgECAgkA2UwE2kl9v+swCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL\n"
            + "VGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUw\n"
            + "EwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATm\n"
            + "K2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI\n"
            + "2xYaHPUdfvGULUvPciLBow0wCzAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUC\n"
            + "IQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGohg/B6dGh5\n"
            + "XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This is a certificate with a pathlen constraint of 10, but there is an unrelated invalid
     * subjectAltNames extension.
     */
    private static final String BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN =
            "-----BEGIN CERTIFICATE-----\n"
            + "MIIBRjCB7aADAgECAgkA2UwE2kl9v+swCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL\n"
            + "VGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUw\n"
            + "EwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATm\n"
            + "K2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI\n"
            + "2xYaHPUdfvGULUvPciLBoyMwITAPBgNVHRMECDAGAQH/AgEKMA4GA1UdEQQHSU5W\n"
            + "QUxJRDAKBggqhkjOPQQDAgNIADBFAiEA8qA1XlE6NsOCeZvuJ1CFjnAGdJVX0il0\n"
            + "APS+FYddxAcCIHweeRRqIYPwenRoeV8UmZpotPHLnhVe5h8yUmFedckU\n"
            + "-----END CERTIFICATE-----\n";

    /**
     * This is a certificate whose keyUsage extension has more than nine bits. The getKeyUsage()
     * method internally rounds up to nine bits, so this tests what happens when it does not need to
     * round.
     */
    private static final String LARGE_KEY_USAGE = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBNjCB3aADAgECAgkA2UwE2kl9v+swCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwL\n"
            + "VGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3WjAXMRUw\n"
            + "EwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATm\n"
            + "K2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8SjHlbifINI\n"
            + "2xYaHPUdfvGULUvPciLBoxMwETAPBgNVHQ8BAf8EBQMDBaAAMAoGCCqGSM49BAMC\n"
            + "A0gAMEUCIQDyoDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGoh\n"
            + "g/B6dGh5XxSZmmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";

    /*
     * OpenSSLX509Certificate needs to compensate for OpenSSL's AlgorithmIdentifier representation
     * by re-encoding the parameter field. Test this behaves correctly against a variety of
     * different parameter types.
     */
    private static final String SIGALG_NO_PARAMETER = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBKTCBzKADAgECAgkA2UwE2kl9v+swDgYMKoZIhvcSBAGEtwkCMBYxFDASBgNV\n"
            + "BAMMC1Rlc3QgSXNzdWVyMB4XDTE0MDQyMzIzMjE1N1oXDTE0MDUyMzIzMjE1N1ow\n"
            + "FzEVMBMGA1UEAwwMVGVzdCBTdWJqZWN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"
            + "QgAE5itp4r9ln5e+Lx4NlIpM1Zdrt6keDUb73ampHp3culoB59aXqAoY+cPEox5W\n"
            + "4nyDSNsWGhz1HX7xlC1Lz3IiwTAOBgwqhkiG9xIEAYS3CQIDSAAwRQIhAPKgNV5R\n"
            + "OjbDgnmb7idQhY5wBnSVV9IpdAD0vhWHXcQHAiB8HnkUaiGD8Hp0aHlfFJmaaLTx\n"
            + "y54VXuYfMlJhXnXJFA==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String SIGALG_NULL_PARAMETER = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBLTCBzqADAgECAgkA2UwE2kl9v+swEAYMKoZIhvcSBAGEtwkCBQAwFjEUMBIG\n"
            + "A1UEAwwLVGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3\n"
            + "WjAXMRUwEwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\n"
            + "BwNCAATmK2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8Sj\n"
            + "HlbifINI2xYaHPUdfvGULUvPciLBMBAGDCqGSIb3EgQBhLcJAgUAA0gAMEUCIQDy\n"
            + "oDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGohg/B6dGh5XxSZ\n"
            + "mmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";
    private static final String SIGALG_STRING_PARAMETER = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBNzCB06ADAgECAgkA2UwE2kl9v+swFQYMKoZIhvcSBAGEtwkCDAVwYXJhbTAW\n"
            + "MRQwEgYDVQQDDAtUZXN0IElzc3VlcjAeFw0xNDA0MjMyMzIxNTdaFw0xNDA1MjMy\n"
            + "MzIxNTdaMBcxFTATBgNVBAMMDFRlc3QgU3ViamVjdDBZMBMGByqGSM49AgEGCCqG\n"
            + "SM49AwEHA0IABOYraeK/ZZ+Xvi8eDZSKTNWXa7epHg1G+92pqR6d3LpaAefWl6gK\n"
            + "GPnDxKMeVuJ8g0jbFhoc9R1+8ZQtS89yIsEwFQYMKoZIhvcSBAGEtwkCDAVwYXJh\n"
            + "bQNIADBFAiEA8qA1XlE6NsOCeZvuJ1CFjnAGdJVX0il0APS+FYddxAcCIHweeRRq\n"
            + "IYPwenRoeV8UmZpotPHLnhVe5h8yUmFedckU\n"
            + "-----END CERTIFICATE-----\n";
    private static final String SIGALG_BOOLEAN_PARAMETER = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBLzCBz6ADAgECAgkA2UwE2kl9v+swEQYMKoZIhvcSBAGEtwkCAQH/MBYxFDAS\n"
            + "BgNVBAMMC1Rlc3QgSXNzdWVyMB4XDTE0MDQyMzIzMjE1N1oXDTE0MDUyMzIzMjE1\n"
            + "N1owFzEVMBMGA1UEAwwMVGVzdCBTdWJqZWN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
            + "AQcDQgAE5itp4r9ln5e+Lx4NlIpM1Zdrt6keDUb73ampHp3culoB59aXqAoY+cPE\n"
            + "ox5W4nyDSNsWGhz1HX7xlC1Lz3IiwTARBgwqhkiG9xIEAYS3CQIBAf8DSAAwRQIh\n"
            + "APKgNV5ROjbDgnmb7idQhY5wBnSVV9IpdAD0vhWHXcQHAiB8HnkUaiGD8Hp0aHlf\n"
            + "FJmaaLTxy54VXuYfMlJhXnXJFA==\n"
            + "-----END CERTIFICATE-----\n";
    private static final String SIGALG_SEQUENCE_PARAMETER = "-----BEGIN CERTIFICATE-----\n"
            + "MIIBLTCBzqADAgECAgkA2UwE2kl9v+swEAYMKoZIhvcSBAGEtwkCMAAwFjEUMBIG\n"
            + "A1UEAwwLVGVzdCBJc3N1ZXIwHhcNMTQwNDIzMjMyMTU3WhcNMTQwNTIzMjMyMTU3\n"
            + "WjAXMRUwEwYDVQQDDAxUZXN0IFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMB\n"
            + "BwNCAATmK2niv2Wfl74vHg2UikzVl2u3qR4NRvvdqakendy6WgHn1peoChj5w8Sj\n"
            + "HlbifINI2xYaHPUdfvGULUvPciLBMBAGDCqGSIb3EgQBhLcJAjAAA0gAMEUCIQDy\n"
            + "oDVeUTo2w4J5m+4nUIWOcAZ0lVfSKXQA9L4Vh13EBwIgfB55FGohg/B6dGh5XxSZ\n"
            + "mmi08cueFV7mHzJSYV51yRQ=\n"
            + "-----END CERTIFICATE-----\n";

    private static final String UTCTIME_WITH_OFFSET = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDPzCCAicCAgERMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVTMRMwEQYD\n"
            + "VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MR8wHQYDVQQK\n"
            + "DBZHb29nbGUgQXV0b21vdGl2ZSBMaW5rMCYXETE0MDcwNDAwMDAwMC0wNzAwFxE0\n"
            + "ODA4MDExMDIxMjMtMDcwMDBnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv\n"
            + "cm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEeMBwGA1UECgwVQW5kcm9pZC1B\n"
            + "dXRvLUludGVybmFsMQswCQYDVQQLDAIwMTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
            + "ADCCAQoCggEBAOWghAac2eJLbi/ijgZGRB6/MuaBVfOImkQddBJUhXbnskTJB/JI\n"
            + "12Ea22E5GeVN8CkWULAZT28yDWqsKMyq9BzpjpsHc9TKxMYqrIn0HP7mIJcBu5z7\n"
            + "K8DoXqc86encncJlkGeuQkUA68yyp7RG7eQ6XoBHEjNmyvX13Y8NY5sPUHfLfmp6\n"
            + "A2n+Jdmecq3L0GS84ctdNtnp2zSopTy0L1Gp6+lrnuOPAYZeV+Ei2jAvhycvuSoB\n"
            + "yV6rT9wvREvC2TDncurMwR6ws44+ZStqkhnvDLhV04ray5aPplQwwB9GELFCYSRk\n"
            + "56sm57uYSJj/LlmOMcvyBmUHVJ7MLxgtlykCAwEAATANBgkqhkiG9w0BAQsFAAOC\n"
            + "AQEA1Bs8v6HuAIiBdhGDGHzZJDwO6lW0LheBqsGLG9KsVvIVrTMPP9lpdTPjStGn\n"
            + "en1RIce4R4l3YTBwxOadLMkf8rymAE5JNjPsWlBue7eI4TFFw/cvnKxcTQ61bC4i\n"
            + "2uosyDI5VfrXm38zYcZoK4TFtMhNyx6aYSEClWB9MjHa+n6eR3dLBCg1kMGqGdZ/\n"
            + "AoK0UEkyI3UFU8sW86iaS4dvPSaQ+z0tmfUzbrc5ZSk4hYCeUYvuyd2ShxjKmxvD\n"
            + "0K8A7gKLY0jP8Zp+6rYBcpxc7cylWMbdlhFTHAGiKI+XeQ/9u+RPeocZsn5jGlDt\n"
            + "K3ftMoWFce+baNq/WcMzRj04AA==\n"
            + "-----END CERTIFICATE-----\n";
    private static Date dateFromUTC(int year, int month, int day, int hour, int minute,
                                    int second) {
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        c.set(year, month, day, hour, minute, second);
        c.set(Calendar.MILLISECOND, 0);
        return c.getTime();
    }

    private static X509Certificate certificateFromPEM(Provider p, String pem)
            throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X509", p);
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    private static List<Pair<Integer, String>> normalizeGeneralNames(Collection<List<?>> names) {
        // Extract a more convenient type than Java's Collection<List<?>>.
        List<Pair<Integer, String>> result = new ArrayList<>();
        for (List<?> tuple : names) {
            assertEquals(2, tuple.size());
            int type = (Integer) tuple.get(0);
            // TODO(davidben): Most name types are expected to have a String value, but some use
            // byte[]. Update this logic when testing those name types. See
            // X509Certificate.getSubjectAlternativeNames().
            String value = (String) tuple.get(1);
            result.add(Pair.of(type, value));
        }
        // Although there is a natural order (the order in the certificate), Java's API returns a
        // Collection, so there is no guarantee of the provider using a particular order. Normalize
        // the order before comparing.
        result.sort(Comparator.comparingInt((Pair<Integer, String> a) -> a.getFirst())
                            .thenComparing(Pair::getSecond));
        return result;
    }

    private static void assertGeneralNamesEqual(Collection<List<?>> expected,
                                                Collection<List<?>> actual) {
        assertEquals(normalizeGeneralNames(expected), normalizeGeneralNames(actual));
    }

    // Error Prone flags Date.equals(), but Instant and LocalDateTime are not available in Java 7.
    // We could compare Date.getTime(), but this trips another warning in Error Prone. We do not use
    // Date subclasses, so stick with Date.equals for now.
    //
    // https://errorprone.info/bugpattern/UndefinedEquals
    @SuppressWarnings("UndefinedEquals")
    private static void assertDatesEqual(Date expected, Date actual) {
        assertEquals(expected, actual);
    }

    // See issue #539.
    @Test
    public void testMismatchedAlgorithm() {
        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
            try {
                X509Certificate c = certificateFromPEM(p, MISMATCHED_ALGORITHM_CERT);
                c.verify(c.getPublicKey());
                fail();
            } catch (CertificateException expected) {
            }
        });
    }

    /**
     * Confirm that explicit EC params aren't accepted in certificates.
     */
    @Test
    public void testExplicitEcParams() {
        ServiceTester.test("CertificateFactory")
                .withAlgorithm("X509")
                // Bouncy Castle allows explicit EC params in certificates, even though they're
                // barred by RFC 5480
                .skipProvider("BC")
                .run((p, algorithm) -> {
                    try {
                        X509Certificate c = certificateFromPEM(p, EC_EXPLICIT_KEY_CERT);
                        c.verify(c.getPublicKey());
                        fail();
                    } catch (InvalidKeyException expected) {
                        // TODO: Should we throw CertificateParsingException at parse time
                        // instead of waiting for when the user accesses the key?
                    } catch (CertificateParsingException expected) {
                    }
                });
    }

    @Test
    public void testRsaCert() {
        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, VALID_CERT);
            assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
            assertEquals("SHA256withRSA", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testEcdsaCert() {
        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, CERT_WITH_ECDSA);
            assertEquals("1.2.840.10045.4.3.2", c.getSigAlgOID());
            assertEquals("SHA256withECDSA", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testRsaPssCert() throws Exception {
    ServiceTester.test("CertificateFactory")
        .withAlgorithm("X509")
        .run(
            (p, algorithm) -> {
              X509Certificate c = certificateFromPEM(p, CERT_WITH_RSA_PSS);
              assertEquals("1.2.840.113549.1.1.10", c.getSigAlgOID());
              assertEquals("RSASSA-PSS", c.getSigAlgName());
              c.verify(c.getPublicKey());
            });
    }

    @Test
    public void testEd25519Cert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        if (!TestUtils.isJavaVersion(18)) {
            // Added because the SUN provider on Java < 18 incorrectly encodes NULL
            // parameters in SubjectPublicKeyInfo. See https://bugs.openjdk.org/browse/JDK-8301793.
            // Conscrypt then rejects the key encoding with a parsing exception.
            tester.skipProvider("SUN");
        }
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, CERT_WITH_ED25519);
            assertEquals("1.3.101.112", c.getSigAlgOID());
            assertEquals("Ed25519", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testMldsaCert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        if (!TestUtils.isJavaVersion(18)) {
            // Added because the SUN provider on Java < 18 incorrectly encodes NULL
            // parameters in SubjectPublicKeyInfo. See https://bugs.openjdk.org/browse/JDK-8301793.
            // Conscrypt then rejects the key encoding with a parsing exception.
            tester.skipProvider("SUN");
        }
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, CERT_WITH_MLDSA44);
            assertEquals("2.16.840.1.101.3.4.3.17", c.getSigAlgOID());
            assertEquals("ML-DSA-44", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testMldsa65Cert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        if (!TestUtils.isJavaVersion(18)) {
            // Added because the SUN provider on Java < 18 incorrectly encodes NULL
            // parameters in SubjectPublicKeyInfo. See https://bugs.openjdk.org/browse/JDK-8301793.
            // Conscrypt then rejects the key encoding with a parsing exception.
            tester.skipProvider("SUN");
        }
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, CERT_WITH_MLDSA65);
            assertEquals("2.16.840.1.101.3.4.3.18", c.getSigAlgOID());
            assertEquals("ML-DSA-65", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testMldsa87Cert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        if (!TestUtils.isJavaVersion(18)) {
            // Added because the SUN provider on Java < 18 incorrectly encodes NULL
            // parameters in SubjectPublicKeyInfo. See https://bugs.openjdk.org/browse/JDK-8301793.
            // Conscrypt then rejects the key encoding with a parsing exception.
            tester.skipProvider("SUN");
        }
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, CERT_WITH_MLDSA87);
            assertEquals("2.16.840.1.101.3.4.3.19", c.getSigAlgOID());
            assertEquals("ML-DSA-87", c.getSigAlgName());
            c.verify(c.getPublicKey());
        });
    }

    @Test
    public void testUnknownSigAlgOID() {
        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, UNKNOWN_SIGNATURE_OID);
            assertEquals("1.2.840.113554.4.1.72585.2", c.getSigAlgOID());
            assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
        });
    }

    // MD5 signed certificates no longer supported by BoringSSL but still supported by OpenJDK 8
    // and by BC where present (up until Android 12)
    @Test
    public void unsupportedDigestType() {
        ServiceTester.test("CertificateFactory")
                .withAlgorithm("X509")
                .skipProvider("SUN")
                .skipProvider("BC")
                .run((p, algorithm) -> {
                    X509Certificate c = certificateFromPEM(p, MD5_SIGNATURE);
                    assertThrows(NoSuchAlgorithmException.class, () -> c.verify(c.getPublicKey()));
                });
    }

    @Test
    public void invalidSignature() {
        // Mutate the signature of VALID_CERT slightly
        int index = VALID_CERT.lastIndexOf('9');
        assertTrue(index > 0);
        String invalidCert = VALID_CERT.substring(0, index) + "8" + VALID_CERT.substring(index + 1);
        ServiceTester.test("CertificateFactory").withAlgorithm("X509").run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, invalidCert);
            assertThrows(SignatureException.class, () -> c.verify(c.getPublicKey()));
        });
    }

    @Test
    public void testV1Cert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, X509V1_CERT);

            // Check basic certificate properties.
            assertEquals(1, c.getVersion());
            assertEquals(new BigInteger("d94c04da497dbfeb", 16), c.getSerialNumber());
            assertDatesEqual(dateFromUTC(2014, Calendar.APRIL, 23, 23, 21, 57), c.getNotBefore());
            assertDatesEqual(dateFromUTC(2014, Calendar.MAY, 23, 23, 21, 57), c.getNotAfter());
            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
            assertEquals("1.2.840.10045.4.1", c.getSigAlgOID());
            String signatureHex = "3045022100f2a0355e513a36c382799bee27"
                    + "50858e7006749557d2297400f4be15875dc4"
                    + "0702207c1e79146a2183f07a7468795f1499"
                    + "9a68b4f1cb9e155ee61f3252615e75c914";
            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());

            // ECDSA signature AlgorithmIdentifiers omit parameters.
            assertNull(c.getSigAlgParams());

            // The certificate does not have UIDs.
            assertNull(c.getIssuerUniqueID());
            assertNull(c.getSubjectUniqueID());

            // The certificate does not have any extensions.
            assertEquals(-1, c.getBasicConstraints());
            assertNull(c.getExtendedKeyUsage());
            assertNull(c.getIssuerAlternativeNames());
            assertNull(c.getKeyUsage());
            assertNull(c.getSubjectAlternativeNames());
        });
    }

    @Test
    public void testManyExtensions() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, MANY_EXTENSIONS);

            assertEquals(3, c.getVersion());
            assertEquals(new BigInteger("b5b622b95a04a521", 16), c.getSerialNumber());
            assertDatesEqual(dateFromUTC(2016, Calendar.JULY, 9, 4, 38, 9), c.getNotBefore());
            assertDatesEqual(dateFromUTC(2016, Calendar.AUGUST, 8, 4, 38, 9), c.getNotAfter());
            assertEquals(new X500Principal("CN=Test Issuer"), c.getIssuerX500Principal());
            assertEquals(new X500Principal("CN=Test Subject"), c.getSubjectX500Principal());
            assertEquals("1.2.840.113549.1.1.11", c.getSigAlgOID());
            String signatureHex = "3ec983af1202b61695ca077d9001f743e6ca"
                    + "bb791fa0fc2d18be5b6462d5f04dc511042e"
                    + "77b3589dac72397850c72c298a783e2f79d2"
                    + "054dfbad8882b22670236fb5be48d427f2fc"
                    + "c34dbabf5f7dab3a5f7df80f485854841378"
                    + "fc85937ba623eda6250aed659c8c3c829263"
                    + "fb181901e11865fac062be18efe88343d093"
                    + "f56ee83f865365d19c357461983596c02c1d"
                    + "ddb55ebc8ae9f0e636410cc1b216aedb38c5"
                    + "ceec711ac61d6cbe88c7faffba7f024fd222"
                    + "270ce174b09a543ca4fc4064fafe1362e855"
                    + "df69329594c295b651bb4ee70b064eb639b0"
                    + "ee39b4534dff2fa3b5485e0750b68a339b1b"
                    + "fb5710b6a2c8274cf92ff069ebafd0c5ed23"
                    + "8c679f50";
            assertArrayEquals(TestUtils.decodeHex(signatureHex), c.getSignature());

            // Although documented to only return null when there are no parameters, the SUN
            // provider also returns null when the algorithm uses an explicit parameter with a
            // value of ASN.1 NULL.
            if (c.getSigAlgParams() != null) {
                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
            }

            assertArrayEquals(new boolean[] {true, false, true, false}, c.getIssuerUniqueID());
            assertArrayEquals(new boolean[] {false, true, false, true, false},
                              c.getSubjectUniqueID());
            assertEquals(10, c.getBasicConstraints());
            assertEquals(Arrays.asList("1.3.6.1.5.5.7.3.1", "1.2.840.113554.4.1.72585.2"),
                         c.getExtendedKeyUsage());

            // TODO(davidben): Test the other name types.
            assertGeneralNamesEqual(
                    Arrays.asList(Arrays.asList(1, "issuer@example.com"),
                                  Arrays.asList(2, "issuer.example.com"),
                                  Arrays.asList(4, "CN=Test Issuer"),
                                  Arrays.asList(6, "https://example.com/issuer"),
                                  // TODO(https://github.com/google/conscrypt/issues/938):
                                  // Fix IPv6 handling and include it in this test.
                                  Arrays.asList(7, "127.0.0.1"),
                                  Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
                    c.getIssuerAlternativeNames());
            assertGeneralNamesEqual(
                    Arrays.asList(Arrays.asList(1, "subject@example.com"),
                                  Arrays.asList(2, "subject.example.com"),
                                  Arrays.asList(4, "CN=Test Subject"),
                                  Arrays.asList(6, "https://example.com/subject"),
                                  // TODO(https://github.com/google/conscrypt/issues/938):
                                  // Fix IPv6 handling and include it in this test.
                                  Arrays.asList(7, "127.0.0.1"),
                                  Arrays.asList(8, "1.2.840.113554.4.1.72585.2")),
                    c.getSubjectAlternativeNames());

            // Although the BIT STRING in the certificate only has three bits, getKeyUsage()
            // rounds up to at least 9 bits.
            assertArrayEquals(
                    new boolean[] {true, false, true, false, false, false, false, false, false},
                    c.getKeyUsage());
        });
    }

    @Test
    public void testBasicConstraints() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.run((p, algorithm) -> {
            // Test some additional edge cases in getBasicConstraints() beyond that
            // testManyExtensions() and testV1Cert() covered.

            // If there is no pathLen constraint but the certificate is a CA,
            // getBasicConstraints() returns Integer.MAX_VALUE.
            X509Certificate c = certificateFromPEM(p, BASIC_CONSTRAINTS_NO_PATHLEN);
            assertEquals(Integer.MAX_VALUE, c.getBasicConstraints());

            // If there is a pathLen constraint of zero, getBasicConstraints() returns it.
            c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_0);
            assertEquals(0, c.getBasicConstraints());

            // If there is basicConstraints extension indicating a leaf certficate,
            // getBasicConstraints() returns -1. The accessor does not distinguish between no
            // basicConstraints extension and a leaf one.
            c = certificateFromPEM(p, BASIC_CONSTRAINTS_LEAF);
            assertEquals(-1, c.getBasicConstraints());

            // If some unrelated extension has a syntax error, and that syntax error does not
            // fail when constructing the certificate, it should not interfere with
            // getBasicConstraints().
            try {
                c = certificateFromPEM(p, BASIC_CONSTRAINTS_PATHLEN_10_BAD_SAN);
            } catch (CertificateParsingException e) {
                // The certificate has a syntax error, so it would also be valid for the
                // provider to reject the certificate at construction. X.509 is an extensible
                // format, so different implementations may notice errors at different points.
                c = null;
            }
            if (c != null) {
                assertEquals(10, c.getBasicConstraints());
            }
        });
    }

    @Test
    public void testLargeKeyUsage() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, LARGE_KEY_USAGE);
            assertArrayEquals(new boolean[] {true, false, true, false, false, false, false, false,
                                             false, false, false},
                              c.getKeyUsage());
        });
    }

    @Test
    public void testSigAlgParams() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.run((p, algorithm) -> {
            X509Certificate c = certificateFromPEM(p, SIGALG_NO_PARAMETER);
            assertNull(c.getSigAlgParams());

            c = certificateFromPEM(p, SIGALG_NULL_PARAMETER);
            // Although documented to only return null when there are no parameters, the SUN
            // provider also returns null when the algorithm uses an explicit parameter with a
            // value of ASN.1 NULL.
            if (c.getSigAlgParams() != null) {
                assertArrayEquals(TestUtils.decodeHex("0500"), c.getSigAlgParams());
            }

            c = certificateFromPEM(p, SIGALG_STRING_PARAMETER);
            assertArrayEquals(TestUtils.decodeHex("0c05706172616d"), c.getSigAlgParams());

            c = certificateFromPEM(p, SIGALG_BOOLEAN_PARAMETER);
            assertArrayEquals(TestUtils.decodeHex("0101ff"), c.getSigAlgParams());

            c = certificateFromPEM(p, SIGALG_SEQUENCE_PARAMETER);
            assertArrayEquals(TestUtils.decodeHex("3000"), c.getSigAlgParams());
        });
    }

    // Ensure we don't reject certificates with UTCTIME fields with offsets for now: b/311260068
    @Test
    public void utcTimeWithOffset() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        tester.skipProvider("SUN") // Sun and BC interpret the offset, Conscrypt just drops it...
                .skipProvider("BC")
                .run((p, algorithm) -> {
                    X509Certificate c = certificateFromPEM(p, UTCTIME_WITH_OFFSET);
                    assertDatesEqual(dateFromUTC(2014, Calendar.JULY, 4, 0, 0, 0),
                                     c.getNotBefore());
                    assertDatesEqual(dateFromUTC(2048, Calendar.AUGUST, 1, 10, 21, 23),
                                     c.getNotAfter());
                });
    }
}
