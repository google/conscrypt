/*
 * Copyright (C) 2011 The Android Open Source Project
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

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ChainStrengthAnalyzerTest {

    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:2048 -sha256 -keyout k.pem -out good.pem
    private static final String GOOD_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDYTCCAkmgAwIBAgIJAPFX8KGuEZcgMA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDDAh0ZXN0LmNvbTAeFw0xMjEwMTUyMTQ0MTBaFw0xMzEwMTUyMTQ0MTBa\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                            "ADCCAQoCggEBAM44hz3eTINuAIS9OYmg6DkUIj3MItn5dgbcMEdbXrhNpeWY93ho\n" +
                            "WQFfsqcSSx28NzqKJmnX+cyinzIUfVde/qciP9P7fxRDokRsf34DJ6gXQplz6P2t\n" +
                            "s4CWjYM+WXJrvEUgLUQ3CBV0CCrtYvG1B9wYsBdAdWkVaMxTvEt7aVxcvJYzp+KU\n" +
                            "ME7HDg0PVxptvUExIskcqKVmW7i748AgBLhd0r1nFWLuH20d42Aowja0Wi19fWl2\n" +
                            "SEMErDRjG8jIPUdSoOLPVLGTktEpex51xnAaZ+I7hy6zs55dq8ua/hE/v2cXIkiQ\n" +
                            "ZXpWyvI/MaKEfeydLnNpa7J3GpH3KW93HQcCAwEAAaNQME4wHQYDVR0OBBYEFA0M\n" +
                            "RI+3hIPCSpVVArisr3Y3/sheMB8GA1UdIwQYMBaAFA0MRI+3hIPCSpVVArisr3Y3\n" +
                            "/sheMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFgUNyuy2qaJvgDO\n" +
                            "plYudTrJR38O3id1B5oKOzgTEgRrfmHHfyloY4fL5gjAGNp7vdlDKSHC2Ebo23/X\n" +
                            "Wg535MJ2296R855jaTMdkSE0+4ASpdmon1D007H0FhLyojlKVta3pqMAF1zsp0YF\n" +
                            "Mf3V/rVMDxCOnbSnqAX0+1nW8Qm4Jgrr3AAMafZk6ypq0xuNQn+sUWuIWw3Xv5Jl\n" +
                            "KehjnuKtMgVYkn2ItRNnUdhm2dQK+Phdb5Yg8WHXN/r9sZQdORg8FQS9TfQJmimB\n" +
                            "CVYuqA9Dt0JJZPuO/Pd1yAxWP4NpxX1xr3lNQ5jrTO702QA3gOrscluULLzrYR50\n" +
                            "FoAjeos=\n" +
                            "-----END CERTIFICATE-----";

    //openssl ecparam -genkey -name prime256v1 -out eckey.pem && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey ec:eckey.pem -sha256 -keyout k.pem -out good.pem
    private static final String GOOD_ECDSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIB1jCCAXugAwIBAgIJALhpH2C1lYeaMAoGCCqGSM49BAMCMEcxCzAJBgNVBAYT\n" +
                            "AlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREwDwYD\n" +
                            "VQQDDAh0ZXN0LmNvbTAeFw0xNDEwMjAyMjUyNDZaFw0xNTEwMjAyMjUyNDZaMEcx\n" +
                            "CzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZp\n" +
                            "bGxlMREwDwYDVQQDDAh0ZXN0LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n" +
                            "BNR++2RWKGFUm+1KTLz7qxrJclPhVNM6gqInvAz2bLo7ENsD5KqN9BbmNvT4eg3y\n" +
                            "u5i+00kiroKcm/35zhNFYamjUDBOMB0GA1UdDgQWBBRJmq9/dKkDW8n8mPzGzuo5\n" +
                            "LcYUKjAfBgNVHSMEGDAWgBRJmq9/dKkDW8n8mPzGzuo5LcYUKjAMBgNVHRMEBTAD\n" +
                            "AQH/MAoGCCqGSM49BAMCA0kAMEYCIQDgq5qudvY9zp3ZhVKEfMLbmwybiM15+wrC\n" +
                            "xp6ipl+GZgIhAKbN/YfYoYlvr6z/xPrZfCZNLEaY/E01PqvD/d91Psa8\n" +
                            "-----END CERTIFICATE-----\n";

    //openssl dsaparam -genkey 1024 -out dsakey.pem && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey dsa:dsakey.pem -sha256 -keyout k.pem -out good.pem
    private static final String GOOD_DSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDHTCCAtugAwIBAgIJAI4X+OBX9ap9MAsGCWCGSAFlAwQDAjBHMQswCQYDVQQG\n" +
                            "EwJVUzERMA8GA1UECAwIVGVzdHNvdGExEjAQBgNVBAcMCVRlc3R2aWxsZTERMA8G\n" +
                            "A1UEAwwIdGVzdC5jb20wHhcNMTQwOTAyMjA1MjUwWhcNMTUwOTAyMjA1MjUwWjBH\n" +
                            "MQswCQYDVQQGEwJVUzERMA8GA1UECAwIVGVzdHNvdGExEjAQBgNVBAcMCVRlc3R2\n" +
                            "aWxsZTERMA8GA1UEAwwIdGVzdC5jb20wggG2MIIBKwYHKoZIzjgEATCCAR4CgYEA\n" +
                            "2QAjoImNX+oSkLdHPDdAzRrbdGdp665OyVBORfdnQeUHbi4WDElqUefTvIWYoDpC\n" +
                            "Dvio284lhTSwXs8H2LKW3xV3AChzaNmPbGwWd4x8zxrE0OSQ+nXgbnBdhlUNUHpa\n" +
                            "AnuuD31eMIDRN6o9WJ7DgksL8aEDO9DRuKUI4TNJKtECFQCB4+ccG9JUCoRh/bnb\n" +
                            "X3cw3BV55wKBgHTmAcAt9Yu6vPdxX6NyzBMwb11kdt/3f0111WCI8nJl/+9mpRDd\n" +
                            "snuPJUzsT00/JMH+puEN2fgOq7QxlCHtgNhX+WUtRE+QFjgvqilM+o+YEWEzeLfp\n" +
                            "kWu/VfM6fV1B3jjmMsie1VNuitVVV1WOE7Pw0rq8m/yXQ5xft0ylhmLSA4GEAAKB\n" +
                            "gH2Q6/2aSPh2b+ePFTLQc20EI6oU6xcyDPKfTsSYH0nUGpr4/k02spVOpHvtUe8e\n" +
                            "1TVS0U30bzdC3bIz2fSUmeU4Kqde4IoZZ3SKjxD0jUKU4/hGuPSAMDEZfPKQIcpj\n" +
                            "UEiqYo+r1ER2u3LdSOqu5ZkYNgT4/C7tr6+NIg1Y4sNuo1AwTjAdBgNVHQ4EFgQU\n" +
                            "PfxTb9tJ6gh4KgFCR6q4Hng1P1AwHwYDVR0jBBgwFoAUPfxTb9tJ6gh4KgFCR6q4\n" +
                            "Hng1P1AwDAYDVR0TBAUwAwEB/zALBglghkgBZQMEAwIDLwAwLAIUNgv+keqfh+sd\n" +
                            "6xqIy6O1QFmjCsMCFB+MYu4K4+BrgPrrMVOnHB4MFHHo\n" +
                            "-----END CERTIFICATE-----";

    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:2048 -md2 -keyout k.pem -out md2.pem
    private static final String MD2_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDuzCCAqOgAwIBAgIJAPgJ74B13cElMA0GCSqGSIb3DQEBAgUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIEwhUZXN0c290YTESMBAGA1UEBxMJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDEwh0ZXN0LmNvbTAeFw0xNDA5MDUwMTMwMDZaFw0xNTA5MDUwMTMwMDZa\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhUZXN0c290YTESMBAGA1UEBxMJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDEwh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                            "ADCCAQoCggEBAMHoaqm+IagQsnbI5fg1shbV4o4RMuxdOdqq35+FUuyGHRm2iUwu\n" +
                            "0KVIX35ZGpzzfbpsOMFSy5XoRdgdG/6zEpYXTNzjGWtZQ/51cwMAVxDFAsrL7bZz\n" +
                            "9mMEbccXOBS6P4mCAVBQmPfjf6YEP9XUFSY4FeD/sfoIwvutQDbkiUKjhUnQzkSl\n" +
                            "JwnIURUqJOonzBVQV+slypYC9GMrXBT+gVq3QaQSkBwQHHr3SAhZfr8nKoxWlPUy\n" +
                            "l/uliZw9LlctlqRegzGo9m1JHHft9E4mqN4DsVfHl/43XE9DVzZwFZlJ2iJ0X2yL\n" +
                            "VXvKPTwZucdXkhl3oW6NHT/u02P9EnSTbEUCAwEAAaOBqTCBpjAdBgNVHQ4EFgQU\n" +
                            "q1g42h7XKGGPlPbgAmmWvlAC2kMwdwYDVR0jBHAwboAUq1g42h7XKGGPlPbgAmmW\n" +
                            "vlAC2kOhS6RJMEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhUZXN0c290YTESMBAG\n" +
                            "A1UEBxMJVGVzdHZpbGxlMREwDwYDVQQDEwh0ZXN0LmNvbYIJAPgJ74B13cElMAwG\n" +
                            "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQECBQADggEBAIz1S5LVYRrmRAKfEaXf0Ja8\n" +
                            "XyxGoE8BlM2WWHQoUO6HX+ixJBFueJT6kFJCH4NPKIZdTmhtKKOKBqJeHKiRom2L\n" +
                            "a+p7GEGondaO/Q+8dqx+S7LUI22CaOss72DHoGFqES37KCs9P8G1gu/5GrQVgfV/\n" +
                            "/UjESMF5/fQuFncgWfn5c6E5z7PRuYOLw3Clym1GbLUwldGeAeVqT4kcIgIKA3Rd\n" +
                            "NqMum8A2TrJlrmtxG4OlkKdpKKjPRhYPYLtPXi/g0p8heJ8/YZSwXGQHrqqOND1F\n" +
                            "fkc4rWxUev50cXXJ4qI8EM0zi3HpBqsqV6JgR8+VMA6MMxPQAWmGbBoztKv1r8U=\n" +
                            "-----END CERTIFICATE-----";

    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:2048 -md4 -keyout k.pem -out md4.pem
    private static final String MD4_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDYTCCAkmgAwIBAgIJAO2CvPpNFLqwMA0GCSqGSIb3DQEBAwUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDDAh0ZXN0LmNvbTAeFw0xNDA5MDQyMjI1MzNaFw0xNTA5MDQyMjI1MzNa\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                            "ADCCAQoCggEBAOQHeENDnuCN08gW/CgIcIYZlD8qgHIc/QgUaHkxbMNBomiOgD8Z\n" +
                            "D1JGtrW6ucbdD66L3Zd5gAfqgGbJ8ySrVFpgXbSpVb6C0wulPZRrm9ll4sZ5BYvg\n" +
                            "zgFhY0TlrizaupZMV+XM3dce/EOYGnrqxWr6jOS7cX3D5Vb9NVE6g+GIW6XKw51Z\n" +
                            "qD+GxxZ2As0lYaZ3vc/+EbiTs/UuIUTsSQvctRkvc83e2vAPtWHX+9ztOLmpSRUP\n" +
                            "8xpganKg5JrfKlXlMXdhJipnOPcYLRMf+UD/7s13TyiQ8Qgt1/h8nirkP8mHYreM\n" +
                            "WenY9Sqrp0FPgGTZbkSnL127mUcWiq+CyasCAwEAAaNQME4wHQYDVR0OBBYEFPSg\n" +
                            "PNT/OJ5IrgrbA7Y0kNgqMp2uMB8GA1UdIwQYMBaAFPSgPNT/OJ5IrgrbA7Y0kNgq\n" +
                            "Mp2uMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEDBQADggEBADg6acU5eqHUDjvG\n" +
                            "M6L+2gMVNiTczlYItLqoibYZW88wzgxpptGKFlWzdl11TIjUaIYqZktfLAWC3Oun\n" +
                            "C564mYPZfaIJEDKNMqcVPiZa9g/8dbctmOxAAvOGdXl+5uk5xOrAsmab7/NH+ksA\n" +
                            "YRpcZntUzbqH33GcMP3CG2i8TM0xM3ZjKch+79asBD/vZmNK1BhsHy3LAE2H2HeA\n" +
                            "k+YDvaBU2yKb0RuZvUmfiySiIjyLtX9JagtHVpcnCZ6pXgCuBy60nGSeP5GQ024x\n" +
                            "GdyN37tmX7gvcazx1+uBlGtw07Uydua4868v/kgu/Ll2zY37CIY6OFi1G0mdk2Xs\n" +
                            "28zzK8s=\n" +
                            "-----END CERTIFICATE-----";

    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:2048 -md5 -keyout k.pem -out md5.pem
    private static final String MD5_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDYTCCAkmgAwIBAgIJAJsffMf2cyx0MA0GCSqGSIb3DQEBBAUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDDAh0ZXN0LmNvbTAeFw0xMjEwMTUyMTQzMzZaFw0xMzEwMTUyMTQzMzZa\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                            "ADCCAQoCggEBAOJyiUwgf/VsdbTTdx6dsb742adeBFBY1FpSWCeQW/JVtdMephbK\n" +
                            "AA00nu8Xq3dNx9bp8AqvzeyHi/RBsZOtb2eAsOXE3RbFy28ehDTHdG34fRQNT6kp\n" +
                            "RUHw8wrUGovMVqS8j+iW8HfAy3sjArje0ygz2NIETlNQbEOifAJtY+AEfZwZE0/0\n" +
                            "IMVP4hwTmIgyReJBDmAx31clwsWZSPar9x+WQfeJ3rfy5LBCtf3RUbdgnvynBHFk\n" +
                            "FjucwoqgOOXviCWxIa0F+ZAmZJBj5+pLN/V92RXOu0c2fR3Mf68J67OJ+K4ueo1N\n" +
                            "nBhRsulWMmGqIVjYOZQxiNzWYcOVXj3DTRMCAwEAAaNQME4wHQYDVR0OBBYEFJbY\n" +
                            "TU06RuJaiMBs2vzx5y0MbaQOMB8GA1UdIwQYMBaAFJbYTU06RuJaiMBs2vzx5y0M\n" +
                            "baQOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADggEBAFEky0jLTmKefDVX\n" +
                            "8O84KoupmQ2qQQBaQF3F5GEuhi0qJRwnmsWkCmsxPP55S67WDFp3JH+LX14UxL4T\n" +
                            "fbG2CXHt/BF1yU3Z8JBwx3bDmfUnUOAFkO3nmByb11FyZTHMzq4jp03DexWREv4q\n" +
                            "Ai5+5Xb56VECgCH/hnGqhQeFGhlZUcSXobVhAU+39L6azWELXxk1K4bpVxYFGn1N\n" +
                            "uZ+dWmb6snPKDzG6J5IIX8QIs6G8H6ptj+QNoU/qTcZEnuzMJxpqMsyq10AA+bY/\n" +
                            "VAYyXeZm3XZrtqYosDeiUdmcL0jjmyQtyOcAoVUQWj1EJuRjXg4BvI6xxRAIPWYT\n" +
                            "EDeWHJE=\n" +
                            "-----END CERTIFICATE-----";

    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:2048 -sha1 -keyout k.pem -out md5.pem
    private static final String SHA1_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDZDCCAkygAwIBAgIJALW5K4gErucTMA0GCSqGSIb3DQEBBQUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDDAh0ZXN0LmNvbTAeFw0xODA0MTIxOTM1MzlaFw0xOTA0MTIxOTM1Mzla\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                            "ADCCAQoCggEBAMAphayEftP2twO/FpfUoERx9Y2DyaSMqvLND5Ay6wDXuLMN6qWX\n" +
                            "3ljtEJW3ZVYM2gEhRIXKKUYt0lyx5EuE0VxrNOVyncr8/SQUY2tYlCSB1LLeOzGB\n" +
                            "sYvVzEon/FUeKlRmcgae9FdqDP/t1pCwVdSxIhYxGoPt+znsbrT2UFO7yBw2WDZa\n" +
                            "P8pLP8VeryXWLyAjX2ezxBNVpxwPBsdssrMRqX2BvsZt9pVx87weBH8Mj1lnGJL2\n" +
                            "4ekfUonSEgT6hhCJv8G6PPvXvV2XWmGzjh+CyaEncoODa5a16JHVmq/BNtK6o/OB\n" +
                            "YNrne86kDCzpruA69JtSYAf9YM2TU8vy6GECAwEAAaNTMFEwHQYDVR0OBBYEFHFu\n" +
                            "2+j9+gNDXIlvtDq7P7A6JYnZMB8GA1UdIwQYMBaAFHFu2+j9+gNDXIlvtDq7P7A6\n" +
                            "JYnZMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBALnB+IOCAuWU\n" +
                            "BEC8AtPzQaBQh2MJhzIg+0HHOGldkMX6jRGRnySf31okZMr9FjLkUMEwyylZvFI1\n" +
                            "fFIdq7a070XAH1u4k/Xx7xi7R0+sfnceaLrt1nvOyhEjitLzLT/+zblMrvY+PvpF\n" +
                            "JkUNSKbd8XkSSMvV3U4bmkAZfP/LIJ8juSrNwzsfIu7IPBq+3yPFZpBR/UNH/NhP\n" +
                            "/9OmD8bLwSer9xAcWFT3JVljtaHmL3D+mP/Q1n2lsb7VhrZ4XESLN8thWxWddRC7\n" +
                            "/72ObwvnJIPGB4Knybv8qee02ZDZRKcjFp872FeIkpHMfG/G/kwQiNzvA6cmwTYQ\n" +
                            "QeVc5iP8Lqo=\n" +
                            "-----END CERTIFICATE-----";


    //openssl ecparam -genkey -name prime256v1 -out eckey.pem && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey ec:eckey.pem -sha1 -keyout k.pem -out sha1.pem
    private static final String SHA1_ECDSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIB1zCCAX2gAwIBAgIJAKS+GaTWit91MAkGByqGSM49BAEwRzELMAkGA1UEBhMC\n" +
                            "VVMxETAPBgNVBAgMCFRlc3Rzb3RhMRIwEAYDVQQHDAlUZXN0dmlsbGUxETAPBgNV\n" +
                            "BAMMCHRlc3QuY29tMB4XDTE4MDQxMjE5NDAyMloXDTE5MDQxMjE5NDAyMlowRzEL\n" +
                            "MAkGA1UEBhMCVVMxETAPBgNVBAgMCFRlc3Rzb3RhMRIwEAYDVQQHDAlUZXN0dmls\n" +
                            "bGUxETAPBgNVBAMMCHRlc3QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n" +
                            "VYHDIpvFu7UBWsfF9G8L5V5Cj+wIGHXIUIYp/GVri9bCTZBkLMqcoNyYKWDKDQb5\n" +
                            "sKuo/CCSo5+1dPSjy8gm8KNTMFEwHQYDVR0OBBYEFI8coJOBd83LFcwx7ypFc7F0\n" +
                            "B7clMB8GA1UdIwQYMBaAFI8coJOBd83LFcwx7ypFc7F0B7clMA8GA1UdEwEB/wQF\n" +
                            "MAMBAf8wCQYHKoZIzj0EAQNJADBGAiEAjXa+FcLuU4jRVf93c4vY8EmATcjFrb4h\n" +
                            "bKrvFxXMUpkCIQCllGWVU3j8Np8DxX0MK2Af/5h8O4zlr9DvPUpCsggaQw==\n" +
                            "-----END CERTIFICATE-----";

    //openssl dsaparam -out dsakey.pem -genkey 1024 && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey dsa:dsakey.pem -sha1 -keyout k.pem -out sha1.pem
    private static final String SHA1_DSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIDHzCCAt2gAwIBAgIJAPO9edaSntPLMAkGByqGSM44BAMwRzELMAkGA1UEBhMC\n" +
                            "VVMxETAPBgNVBAgMCFRlc3Rzb3RhMRIwEAYDVQQHDAlUZXN0dmlsbGUxETAPBgNV\n" +
                            "BAMMCHRlc3QuY29tMB4XDTE4MDQxMjE5NTAyN1oXDTE5MDQxMjE5NTAyN1owRzEL\n" +
                            "MAkGA1UEBhMCVVMxETAPBgNVBAgMCFRlc3Rzb3RhMRIwEAYDVQQHDAlUZXN0dmls\n" +
                            "bGUxETAPBgNVBAMMCHRlc3QuY29tMIIBtzCCASwGByqGSM44BAEwggEfAoGBAMZy\n" +
                            "BYuw9s+UFLnrErRwysU2dfcY0tv4b8FIi63JtF12kTborQkyxilNtDDtBVEA0mKE\n" +
                            "13dvd8JQx2+d6LwHSiaaS2n2/XofVn61HmDNPns1zV8m9XvUX8Cqmz0+1dgyZx0Y\n" +
                            "dP+eg2BjfhfX/6tXWXMd2t2+y3sJalLh9KeC/LftAhUA2RmeKHbNMj9pC9wOj8Yj\n" +
                            "u239Q1ECgYEAhnfB/Z2S/lYc2c78PU2DcChXsj+Mp8ITUwTVg+G4+WvqGzX6FFzr\n" +
                            "9/eTrn+rPLkKDJonHW/OZyVFK2mVQ/s5xE8Wn9YDUYkNPlJ/dFB+okmhZE8hDRwF\n" +
                            "LsgtrLgJqpOEw54b37hyqdvk2vtHI+ANU+jZONRdsmWT9HZ0ryJGqY8DgYQAAoGA\n" +
                            "U8tXEXYh4oCAGLG+S7aNI73LN+a/n0r1aSJM8XuNExZus/eaXCHqEreUi/SBXVEm\n" +
                            "UJEXnsRwzLyErE24yBlQzLBoMbHqJnIOJRmxjrQ7xo9vivo53woIbxHSRdWlzfwW\n" +
                            "14yR5dSVDEVI30TTT/zAoNIWvegHXO2LCeEZ/ilLPxCjUzBRMB0GA1UdDgQWBBQB\n" +
                            "cKP86kuQ/GEG+n0NdJK7A9uBOTAfBgNVHSMEGDAWgBQBcKP86kuQ/GEG+n0NdJK7\n" +
                            "A9uBOTAPBgNVHRMBAf8EBTADAQH/MAkGByqGSM44BAMDMQAwLgIVAIIMd1qgBuGf\n" +
                            "zY7SmaNFYmeQV2qpAhUAkPFti47uD7JjdAEqJ/nFMhYcolQ=\n" +
                            "-----END CERTIFICATE-----";


    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey rsa:512 -sha256 -keyout k.pem -out short.pem
    private static final String SHORT_RSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIB1zCCAYGgAwIBAgIJAOxaz9TreDNIMA0GCSqGSIb3DQEBCwUAMEcxCzAJBgNV\n" +
                            "BAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREw\n" +
                            "DwYDVQQDDAh0ZXN0LmNvbTAeFw0xMjEwMTUyMTQzMjNaFw0xMzEwMTUyMTQzMjNa\n" +
                            "MEcxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVz\n" +
                            "dHZpbGxlMREwDwYDVQQDDAh0ZXN0LmNvbTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgC\n" +
                            "QQCoMgxK9HG0L+hXEht1mKq6ApN3+3lmIEVUcWQKL7EMmn9+L6rVSJyOAGwpTVG7\n" +
                            "eZ5uulC0Lkm5/bzKFSrCf1jlAgMBAAGjUDBOMB0GA1UdDgQWBBTda66RZsgUvR4e\n" +
                            "2RSsq65K1xcz0jAfBgNVHSMEGDAWgBTda66RZsgUvR4e2RSsq65K1xcz0jAMBgNV\n" +
                            "HRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA0EAZWYgoNDn6yEzcmWgsYnG3w2BT6fL\n" +
                            "Npi0+APKWkwxnEJk1kgpdeSTMgaHAphQ8qksHnSgeBAJSs2ZCQMinVPgOg==\n" +
                            "-----END CERTIFICATE-----";

    //openssl dsaparam -genkey 768 -out dsakey.pem && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey dsa:dsakey.pem -sha256 -keyout k.pem -out short.pem
    private static final String SHORT_DSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIICuDCCAnWgAwIBAgIJAMQeQVxVNTKRMAsGCWCGSAFlAwQDAjBHMQswCQYDVQQG\n" +
                            "EwJVUzERMA8GA1UECAwIVGVzdHNvdGExEjAQBgNVBAcMCVRlc3R2aWxsZTERMA8G\n" +
                            "A1UEAwwIdGVzdC5jb20wHhcNMTQwOTAyMjAzNjQ4WhcNMTUwOTAyMjAzNjQ4WjBH\n" +
                            "MQswCQYDVQQGEwJVUzERMA8GA1UECAwIVGVzdHNvdGExEjAQBgNVBAcMCVRlc3R2\n" +
                            "aWxsZTERMA8GA1UEAwwIdGVzdC5jb20wggFQMIHoBgcqhkjOOAQBMIHcAmEApVZC\n" +
                            "vx5pcu5CjEv0n5M0PVxnX/4ZkJn8EAnkgn5P37KxDm7dIHcMw71Epd+l7hP4TLUV\n" +
                            "etW9VOu1ybo+hOMr3IGqlaMVHxL5VWk6DGFjo5ZplF5QGQt+hqFYX8agruoFAhUA\n" +
                            "xsTsmLlEe97rZm2UfNt51tXoQgECYA1dMDAfVUqfC06LJ0O5Q2RmjbkqCLfwiXvq\n" +
                            "q0LVqxQJBVzmjbWoNRdmZpzhjOfMQ2bpQwTj+M4t2YPGifQTgumUolutWGEs7jxU\n" +
                            "HcybdA8/3fqubZ/pEKrz1FhjIReuJgNjAAJgEWAocKA/8Q7pFQ7tkJDUTctU7ZUN\n" +
                            "O9eUqghBkJAaHhjq8GJ/UIoPuS8PCz19/xDZICMhbKpobi+z/sy3atZLtcrrUhN1\n" +
                            "XBgEPD6aWSP3qEBzz2a6MqL6RegDL3ldrRMjo1AwTjAdBgNVHQ4EFgQUk7IR6KN+\n" +
                            "Lb8ZlDs4v1pKtmQans0wHwYDVR0jBBgwFoAUk7IR6KN+Lb8ZlDs4v1pKtmQans0w\n" +
                            "DAYDVR0TBAUwAwEB/zALBglghkgBZQMEAwIDMAAwLQIUG9is/MhJ0qXggCtPiOdH\n" +
                            "UZSNrCgCFQDBb443MntlcWrx5gV7YRd52k0Yug==\n" +
                            "-----END CERTIFICATE-----";

    //ecparam -genkey -name secp128r1 -out eckey.pem && \
    //openssl req -x509 -nodes -days 365 -subj '/C=US/ST=Testsota/L=Testville/CN=test.com' \
    //-newkey ec:eckey.pem -sha256 -keyout k.pem -out short.pem
    private static final String SHORT_ECDSA_PEM = "" +
                            "-----BEGIN CERTIFICATE-----\n" +
                            "MIIBkTCCAVigAwIBAgIJAKogErAsYuahMAoGCCqGSM49BAMCMEcxCzAJBgNVBAYT\n" +
                            "AlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZpbGxlMREwDwYD\n" +
                            "VQQDDAh0ZXN0LmNvbTAeFw0xNDA5MDIyMDQ1MjdaFw0xNTA5MDIyMDQ1MjdaMEcx\n" +
                            "CzAJBgNVBAYTAlVTMREwDwYDVQQIDAhUZXN0c290YTESMBAGA1UEBwwJVGVzdHZp\n" +
                            "bGxlMREwDwYDVQQDDAh0ZXN0LmNvbTA2MBAGByqGSM49AgEGBSuBBAAcAyIABE9Z\n" +
                            "bL28dyGE/sRmSUB0kqdsmkaKaC7gu+9A4CLDO5kJo1AwTjAdBgNVHQ4EFgQU7f+b\n" +
                            "vrGRimukkorDkERufEFRaj0wHwYDVR0jBBgwFoAU7f+bvrGRimukkorDkERufEFR\n" +
                            "aj0wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgMnADAkAhBXRMkfHNexPXaqzJwT\n" +
                            "9eAwAhAzX+1NE+FY0kk74wH83Cz0\n" +
                            "-----END CERTIFICATE-----";


    @Test
    public void testMD2() throws Exception {
        assertBad(MD2_RSA_PEM, "Weak hash check did not fail as expected");
    }

    @Test
    public void testMD4() throws Exception {
        assertBad(MD4_RSA_PEM, "Weak hash check did not fail as expected");
    }

    @Test
    public void testMD5() throws Exception {
        assertBad(MD5_RSA_PEM, "Weak hash check did not fail as expected");
    }

    @Test
    public void testSHA1() throws Exception {
        assertBad(SHA1_RSA_PEM, "Weak SHA1 RSA signature did not fail as expected");
        assertBad(SHA1_ECDSA_PEM, "Weak SHA1 ECDSA signature did not fail as expected");
        assertBad(SHA1_DSA_PEM, "Weak SHA1 DSA signature did not fail as expected");
    }

    @Test
    public void testRsa512() throws Exception {
        assertBad(SHORT_RSA_PEM, "Short RSA modulus check did not fail as expected");
    }

    @Test
    public void testDsa768() throws Exception {
        assertBad(SHORT_DSA_PEM, "Short DSA key check did not fail as expected");
    }

    @Test
    public void testEcdsa128() throws Exception {
        assertBad(SHORT_ECDSA_PEM, "Short EC key check did not fail as expected");
    }

    @Test
    public void testGoodChain() throws Exception {
        assertGood(GOOD_RSA_PEM);
        assertGood(GOOD_DSA_PEM);
        assertGood(GOOD_ECDSA_PEM);
    }

    private static void assertBad(String pem, String msg) throws Exception {
        try {
            check(createCert(pem));
            fail(msg);
        } catch (CertificateException expected) {
        } catch (NoSuchAlgorithmException expected) {
            // Some weak EC groups can no longer be parsed.
        }
    }

    private static void assertGood(String pem) throws Exception {
        check(createCert(pem));
    }

    private static void check(X509Certificate cert) throws Exception {
        X509Certificate[] chain = {cert};
        ChainStrengthAnalyzer.check(chain);
    }

    private static X509Certificate createCert(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        InputStream pemInput = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
        return (X509Certificate) cf.generateCertificate(pemInput);
    }
}
