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
    public void testEd25519Cert() {
        ServiceTester tester = ServiceTester.test("CertificateFactory").withAlgorithm("X509");
        if (!TestUtils.isJavaVersion(18)) {
            // Added because this test fails on Java 17 for unknown reasons.
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
            // Added because this test fails on Java 17 for unknown reasons.
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
