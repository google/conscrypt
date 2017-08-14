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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class TestSessionBuilder {
    private int type;

    private boolean sessionDataSet;
    private byte[] sessionData;
    private int sessionDataLength;

    private boolean certificatesSet;
    private ArrayList<byte[]> certificates = new ArrayList<byte[]>();
    private int certificatesLength;
    private ArrayList<Integer> certificateLengths = new ArrayList<Integer>();

    private boolean ocspDataSet;
    private ArrayList<byte[]> ocspDatas = new ArrayList<byte[]>();
    private int ocspDatasLength;
    private ArrayList<Integer> ocspDataLengths = new ArrayList<Integer>();

    private boolean tlsSctDataSet;
    private byte[] tlsSctData;
    private int tlsSctDataLength;

    public TestSessionBuilder setType(int type) {
        this.type = type;
        return this;
    }

    public TestSessionBuilder setSessionData(byte[] sessionData) {
        sessionDataSet = true;
        this.sessionData = sessionData;
        sessionDataLength = sessionData.length;
        return this;
    }

    public TestSessionBuilder setSessionDataLength(int sessionDataLength) {
        assertTrue("call setSessionData first", sessionDataSet);
        this.sessionDataLength = sessionDataLength;
        return this;
    }

    public TestSessionBuilder addCertificate(byte[] certificate) {
        certificatesSet = true;
        certificates.add(certificate);
        certificateLengths.add(certificate.length);
        certificatesLength = certificates.size();
        return this;
    }

    public TestSessionBuilder setCertificatesLength(int certificatesLength) {
        assertTrue("call addCertificate first", certificatesSet);
        this.certificatesLength = certificatesLength;
        return this;
    }

    public TestSessionBuilder setCertificateLength(int certIndex, int certLength) {
        assertTrue("call addCertificate first", certificatesSet);
        certificateLengths.set(certIndex, certLength);
        return this;
    }

    public TestSessionBuilder setOcspDataEmpty() {
        ocspDataSet = true;
        return this;
    }

    public TestSessionBuilder addOcspData(byte[] ocspData) {
        ocspDataSet = true;
        ocspDatas.add(ocspData);
        ocspDataLengths.add(ocspData.length);
        ocspDatasLength = ocspDatas.size();
        return this;
    }

    public TestSessionBuilder setOcspDatasLength(int ocspDatasLength) {
        assertTrue("Call addOcspData before setting length", ocspDataSet);
        this.ocspDatasLength = ocspDatasLength;
        return this;
    }

    public TestSessionBuilder setOcspDataLength(int ocspDataIndex, int ocspDataLength) {
        assertTrue("Call addOcspData before setting length", ocspDataSet);
        this.ocspDataLengths.set(ocspDataIndex, ocspDataLength);
        return this;
    }

    public TestSessionBuilder setTlsSctData(byte[] tlsSctData) {
        tlsSctDataSet = true;
        this.tlsSctData = tlsSctData.clone();
        tlsSctDataLength = tlsSctData.length;
        return this;
    }

    public TestSessionBuilder setTlsSctDataLength(int tlsSctDataLength) {
        assertTrue("Call setTlsSctData before setting length", tlsSctDataSet);
        this.tlsSctDataLength = tlsSctDataLength;
        return this;
    }

    public TestSessionBuilder setTlsSctDataEmpty() {
        tlsSctDataSet = true;
        return this;
    }

    public byte[] build() {
        assertTrue("Must set session data", sessionDataSet);
        assertTrue("Must call addCertificate at least once", certificatesSet);

        ByteBuffer buf = ByteBuffer.allocate(4096);
        buf.putInt(type);

        buf.putInt(sessionDataLength);
        buf.put(sessionData);

        buf.putInt(certificatesLength);
        for (int i = 0; i < certificates.size(); i++) {
            buf.putInt(certificateLengths.get(i));
            buf.put(certificates.get(i));
        }

        if (ocspDataSet) {
            buf.putInt(ocspDatasLength);
            for (int i = 0; i < ocspDatas.size(); i++) {
                buf.putInt(ocspDataLengths.get(i));
                buf.put(ocspDatas.get(i));
            }

            if (tlsSctDataSet) {
                if (tlsSctData == null) {
                    buf.putInt(0);
                } else {
                    buf.putInt(tlsSctDataLength);
                    buf.put(tlsSctData);
                }
            }
        } else {
            assertFalse("If ocspData is not set, then tlsSctData must not be set", tlsSctDataSet);
        }

        buf.flip();
        byte[] output = new byte[buf.remaining()];
        buf.get(output);
        return output;
    }
}
