/*
 * Copyright 2016 The Android Open Source Project
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

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TestSessionBuilderTest {
    @Test
    public void buildsValidBasicSession() {
        assertArrayEquals(new byte[] {0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x22, 0x00,
                                  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x33},
                new TestSessionBuilder()
                        .setType(0x11)
                        .setSessionData(new byte[] {0x22})
                        .addCertificate(new byte[] {0x33})
                        .build());
    }

    @Test
    public void buildsValidOcspSession() {
        assertArrayEquals(
                new byte[] {
                        0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x22, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x01, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                        0x00, 0x01, 0x44,
                },
                new TestSessionBuilder()
                        .setType(0x11)
                        .setSessionData(new byte[] {0x22})
                        .addCertificate(new byte[] {0x33})
                        .addOcspData(new byte[] {0x44})
                        .build());
    }

    @Test
    public void buildsValidOcspAndTlsSctSession() {
        assertArrayEquals(
                new byte[] {
                        0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x22, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x01, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                        0x00, 0x01, 0x44, 0x00, 0x00, 0x00, 0x01, 0x55,
                },
                new TestSessionBuilder()
                        .setType(0x11)
                        .setSessionData(new byte[] {0x22})
                        .addCertificate(new byte[] {0x33})
                        .addOcspData(new byte[] {0x44})
                        .setTlsSctData(new byte[] {0x55})
                        .build());
    }

    @Test
    public void buildsValidButEmptyOcspAndTlsSctSession() {
        assertArrayEquals(
                new byte[] {
                        0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x22, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0x00, 0x00, 0x01, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00,
                },
                new TestSessionBuilder()
                        .setType(0x11)
                        .setSessionData(new byte[] {0x22})
                        .addCertificate(new byte[] {0x33})
                        .setOcspDataEmpty()
                        .setTlsSctDataEmpty()
                        .build());
    }

    @Test
    public void buildsInvalidOcspAndTlsSctSession() {
        assertArrayEquals(
                new byte[] {
                        0x00, 0x00, 0x00, 0x11, 0x00, 0x33, 0x22, 0x11, 0x22, 0x12, 0x11, 0x22,
                        0x34, 0x10, 0x20, 0x30, 0x40, 0x33, 0x38, 0x48, 0x18, 0x28, 0x13, 0x24,
                        0x57, 0x68, 0x44, (byte) 0x99, (byte) 0x88, 0x77, 0x66, 0x55,
                },
                new TestSessionBuilder()
                        .setType(0x11)
                        .setSessionData(new byte[] {0x22})
                        .setSessionDataLength(0x332211)
                        .addCertificate(new byte[] {0x33})
                        .setCertificatesLength(0x12112234)
                        .setCertificateLength(0, 0x10203040)
                        .addOcspData(new byte[] {0x44})
                        .setOcspDatasLength(0x38481828)
                        .setOcspDataLength(0, 0x13245768)
                        .setTlsSctData(new byte[] {0x55})
                        .setTlsSctDataLength(0x99887766)
                        .build());
    }
}
