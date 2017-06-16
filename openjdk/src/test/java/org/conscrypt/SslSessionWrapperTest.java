/*
 * Copyright 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License", "www.google.com", 443);
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SslSessionWrapperTest {
    /*
     * Taken from external/boringssl/src/ssl/ssl_test.cc: kOpenSSLSession is a
     * serialized SSL_SESSION.
     */
    private static final byte[] kOpenSSLSession = new byte[] {(byte) 0x30, (byte) 0x82, (byte) 0x05,
            (byte) 0xAA, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x02,
            (byte) 0x03, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0xC0, (byte) 0x2F,
            (byte) 0x04, (byte) 0x20, (byte) 0x06, (byte) 0xE5, (byte) 0x0D, (byte) 0x67,
            (byte) 0x76, (byte) 0xAE, (byte) 0x18, (byte) 0x7E, (byte) 0x66, (byte) 0xDE,
            (byte) 0xA3, (byte) 0x5C, (byte) 0xF0, (byte) 0x2E, (byte) 0x43, (byte) 0x51,
            (byte) 0x2A, (byte) 0x60, (byte) 0x97, (byte) 0x19, (byte) 0xD3, (byte) 0x60,
            (byte) 0x5A, (byte) 0xF1, (byte) 0x93, (byte) 0xDD, (byte) 0xCB, (byte) 0x24,
            (byte) 0x57, (byte) 0x4C, (byte) 0x90, (byte) 0x90, (byte) 0x04, (byte) 0x30,
            (byte) 0x26, (byte) 0x5A, (byte) 0xE5, (byte) 0xCE, (byte) 0x40, (byte) 0x16,
            (byte) 0x04, (byte) 0xE5, (byte) 0xA2, (byte) 0x2E, (byte) 0x3F, (byte) 0xE3,
            (byte) 0x27, (byte) 0xBE, (byte) 0x83, (byte) 0xEE, (byte) 0x5F, (byte) 0x94,
            (byte) 0x5E, (byte) 0x88, (byte) 0xB3, (byte) 0x3F, (byte) 0x62, (byte) 0x88,
            (byte) 0xD8, (byte) 0x2E, (byte) 0xC8, (byte) 0xD8, (byte) 0x57, (byte) 0x1C,
            (byte) 0xA8, (byte) 0xC9, (byte) 0x88, (byte) 0x7C, (byte) 0x59, (byte) 0xA6,
            (byte) 0x91, (byte) 0x4C, (byte) 0xB7, (byte) 0xDA, (byte) 0x72, (byte) 0x09,
            (byte) 0xD2, (byte) 0x66, (byte) 0x47, (byte) 0x21, (byte) 0x6A, (byte) 0x09,
            (byte) 0xA1, (byte) 0x06, (byte) 0x02, (byte) 0x04, (byte) 0x54, (byte) 0x43,
            (byte) 0x3B, (byte) 0x8E, (byte) 0xA2, (byte) 0x04, (byte) 0x02, (byte) 0x02,
            (byte) 0x01, (byte) 0x2C, (byte) 0xA3, (byte) 0x82, (byte) 0x04, (byte) 0x7A,
            (byte) 0x30, (byte) 0x82, (byte) 0x04, (byte) 0x76, (byte) 0x30, (byte) 0x82,
            (byte) 0x03, (byte) 0x5E, (byte) 0xA0, (byte) 0x03, (byte) 0x02, (byte) 0x01,
            (byte) 0x02, (byte) 0x02, (byte) 0x08, (byte) 0x2B, (byte) 0xD7, (byte) 0x54,
            (byte) 0xBE, (byte) 0xC3, (byte) 0xD6, (byte) 0x4A, (byte) 0x55, (byte) 0x30,
            (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x05,
            (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x49, (byte) 0x31, (byte) 0x0B,
            (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31,
            (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x04, (byte) 0x0A, (byte) 0x13, (byte) 0x0A, (byte) 0x47, (byte) 0x6F,
            (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65, (byte) 0x20, (byte) 0x49,
            (byte) 0x6E, (byte) 0x63, (byte) 0x31, (byte) 0x25, (byte) 0x30, (byte) 0x23,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13,
            (byte) 0x1C, (byte) 0x47, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C,
            (byte) 0x65, (byte) 0x20, (byte) 0x49, (byte) 0x6E, (byte) 0x74, (byte) 0x65,
            (byte) 0x72, (byte) 0x6E, (byte) 0x65, (byte) 0x74, (byte) 0x20, (byte) 0x41,
            (byte) 0x75, (byte) 0x74, (byte) 0x68, (byte) 0x6F, (byte) 0x72, (byte) 0x69,
            (byte) 0x74, (byte) 0x79, (byte) 0x20, (byte) 0x47, (byte) 0x32, (byte) 0x30,
            (byte) 0x1E, (byte) 0x17, (byte) 0x0D, (byte) 0x31, (byte) 0x34, (byte) 0x31,
            (byte) 0x30, (byte) 0x30, (byte) 0x38, (byte) 0x31, (byte) 0x32, (byte) 0x30,
            (byte) 0x37, (byte) 0x35, (byte) 0x37, (byte) 0x5A, (byte) 0x17, (byte) 0x0D,
            (byte) 0x31, (byte) 0x35, (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x36,
            (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x5A, (byte) 0x30, (byte) 0x68, (byte) 0x31, (byte) 0x0B, (byte) 0x30,
            (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06,
            (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x13,
            (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x08, (byte) 0x0C, (byte) 0x0A, (byte) 0x43, (byte) 0x61, (byte) 0x6C,
            (byte) 0x69, (byte) 0x66, (byte) 0x6F, (byte) 0x72, (byte) 0x6E, (byte) 0x69,
            (byte) 0x61, (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0C, (byte) 0x0D,
            (byte) 0x4D, (byte) 0x6F, (byte) 0x75, (byte) 0x6E, (byte) 0x74, (byte) 0x61,
            (byte) 0x69, (byte) 0x6E, (byte) 0x20, (byte) 0x56, (byte) 0x69, (byte) 0x65,
            (byte) 0x77, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A, (byte) 0x0C, (byte) 0x0A,
            (byte) 0x47, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65,
            (byte) 0x20, (byte) 0x49, (byte) 0x6E, (byte) 0x63, (byte) 0x31, (byte) 0x17,
            (byte) 0x30, (byte) 0x15, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
            (byte) 0x03, (byte) 0x0C, (byte) 0x0E, (byte) 0x77, (byte) 0x77, (byte) 0x77,
            (byte) 0x2E, (byte) 0x67, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C,
            (byte) 0x65, (byte) 0x2E, (byte) 0x63, (byte) 0x6F, (byte) 0x6D, (byte) 0x30,
            (byte) 0x82, (byte) 0x01, (byte) 0x22, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
            (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7,
            (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00,
            (byte) 0x03, (byte) 0x82, (byte) 0x01, (byte) 0x0F, (byte) 0x00, (byte) 0x30,
            (byte) 0x82, (byte) 0x01, (byte) 0x0A, (byte) 0x02, (byte) 0x82, (byte) 0x01,
            (byte) 0x01, (byte) 0x00, (byte) 0x9C, (byte) 0x29, (byte) 0xE2, (byte) 0xEB,
            (byte) 0xA6, (byte) 0x50, (byte) 0x02, (byte) 0xF8, (byte) 0xBA, (byte) 0x1F,
            (byte) 0xCB, (byte) 0xCB, (byte) 0x7F, (byte) 0xC0, (byte) 0x3C, (byte) 0x2D,
            (byte) 0x07, (byte) 0xA7, (byte) 0xAE, (byte) 0xEF, (byte) 0x60, (byte) 0x95,
            (byte) 0xA7, (byte) 0x47, (byte) 0x09, (byte) 0xE1, (byte) 0x5D, (byte) 0xE5,
            (byte) 0x92, (byte) 0x73, (byte) 0x7A, (byte) 0x86, (byte) 0xE1, (byte) 0xFD,
            (byte) 0x72, (byte) 0xDE, (byte) 0x85, (byte) 0x16, (byte) 0x4E, (byte) 0xF4,
            (byte) 0xA1, (byte) 0x12, (byte) 0x21, (byte) 0xFD, (byte) 0x50, (byte) 0x4D,
            (byte) 0x04, (byte) 0x1C, (byte) 0xFD, (byte) 0xD3, (byte) 0x48, (byte) 0xD8,
            (byte) 0xCB, (byte) 0xEE, (byte) 0xF5, (byte) 0xD7, (byte) 0x52, (byte) 0x66,
            (byte) 0xD5, (byte) 0xBF, (byte) 0x22, (byte) 0xA8, (byte) 0xE4, (byte) 0xD0,
            (byte) 0xF5, (byte) 0xA4, (byte) 0xF9, (byte) 0x0B, (byte) 0xB4, (byte) 0x84,
            (byte) 0x84, (byte) 0xD7, (byte) 0x10, (byte) 0x14, (byte) 0x9B, (byte) 0xEA,
            (byte) 0xCC, (byte) 0x7D, (byte) 0xDE, (byte) 0x30, (byte) 0xF9, (byte) 0x1B,
            (byte) 0xE9, (byte) 0x94, (byte) 0x96, (byte) 0x1A, (byte) 0x6D, (byte) 0x72,
            (byte) 0x18, (byte) 0x5E, (byte) 0xCC, (byte) 0x09, (byte) 0x04, (byte) 0xC6,
            (byte) 0x41, (byte) 0x71, (byte) 0x76, (byte) 0xD1, (byte) 0x29, (byte) 0x3F,
            (byte) 0x3B, (byte) 0x5E, (byte) 0x85, (byte) 0x4A, (byte) 0x30, (byte) 0x32,
            (byte) 0x9D, (byte) 0x4F, (byte) 0xDB, (byte) 0xDE, (byte) 0x82, (byte) 0x66,
            (byte) 0x39, (byte) 0xCB, (byte) 0x5C, (byte) 0xC9, (byte) 0xC5, (byte) 0x98,
            (byte) 0x91, (byte) 0x8D, (byte) 0x32, (byte) 0xB5, (byte) 0x2F, (byte) 0xE4,
            (byte) 0xDC, (byte) 0xB0, (byte) 0x6E, (byte) 0x21, (byte) 0xDE, (byte) 0x39,
            (byte) 0x3C, (byte) 0x96, (byte) 0xA8, (byte) 0x32, (byte) 0xA8, (byte) 0xC1,
            (byte) 0xD1, (byte) 0x6C, (byte) 0xA9, (byte) 0xAA, (byte) 0xF3, (byte) 0x5E,
            (byte) 0x24, (byte) 0x70, (byte) 0xB7, (byte) 0xAB, (byte) 0x92, (byte) 0x63,
            (byte) 0x08, (byte) 0x1E, (byte) 0x11, (byte) 0x3F, (byte) 0xB3, (byte) 0x5F,
            (byte) 0xC7, (byte) 0x98, (byte) 0xE3, (byte) 0x1D, (byte) 0x2A, (byte) 0xC2,
            (byte) 0x32, (byte) 0x1C, (byte) 0x3C, (byte) 0x95, (byte) 0x43, (byte) 0x16,
            (byte) 0xE0, (byte) 0x46, (byte) 0x83, (byte) 0xC6, (byte) 0x36, (byte) 0x91,
            (byte) 0xF4, (byte) 0xA0, (byte) 0xE1, (byte) 0x3C, (byte) 0xB8, (byte) 0x23,
            (byte) 0xB2, (byte) 0x4F, (byte) 0x8B, (byte) 0x0C, (byte) 0x8C, (byte) 0x92,
            (byte) 0x45, (byte) 0x24, (byte) 0x43, (byte) 0x68, (byte) 0x24, (byte) 0x06,
            (byte) 0x84, (byte) 0x43, (byte) 0x96, (byte) 0x2C, (byte) 0x96, (byte) 0x55,
            (byte) 0x2F, (byte) 0x32, (byte) 0xE8, (byte) 0xE0, (byte) 0xDE, (byte) 0xBF,
            (byte) 0x52, (byte) 0x57, (byte) 0x2D, (byte) 0x08, (byte) 0x71, (byte) 0x25,
            (byte) 0x96, (byte) 0x90, (byte) 0x54, (byte) 0x4A, (byte) 0xF1, (byte) 0x0E,
            (byte) 0xC8, (byte) 0x58, (byte) 0x1A, (byte) 0xE7, (byte) 0x6A, (byte) 0xAB,
            (byte) 0xA0, (byte) 0x68, (byte) 0xE0, (byte) 0xAD, (byte) 0xFD, (byte) 0xD6,
            (byte) 0x39, (byte) 0x0F, (byte) 0x76, (byte) 0xE4, (byte) 0xC1, (byte) 0x70,
            (byte) 0xCD, (byte) 0xDE, (byte) 0x80, (byte) 0x2B, (byte) 0xE2, (byte) 0x1C,
            (byte) 0x87, (byte) 0x48, (byte) 0x03, (byte) 0x46, (byte) 0x0F, (byte) 0x2C,
            (byte) 0x41, (byte) 0xF7, (byte) 0x4B, (byte) 0x1F, (byte) 0x93, (byte) 0xAE,
            (byte) 0x3F, (byte) 0x57, (byte) 0x1F, (byte) 0x2D, (byte) 0xF5, (byte) 0x35,
            (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xA3,
            (byte) 0x82, (byte) 0x01, (byte) 0x41, (byte) 0x30, (byte) 0x82, (byte) 0x01,
            (byte) 0x3D, (byte) 0x30, (byte) 0x1D, (byte) 0x06, (byte) 0x03, (byte) 0x55,
            (byte) 0x1D, (byte) 0x25, (byte) 0x04, (byte) 0x16, (byte) 0x30, (byte) 0x14,
            (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x05,
            (byte) 0x05, (byte) 0x07, (byte) 0x03, (byte) 0x01, (byte) 0x06, (byte) 0x08,
            (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
            (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x19, (byte) 0x06, (byte) 0x03,
            (byte) 0x55, (byte) 0x1D, (byte) 0x11, (byte) 0x04, (byte) 0x12, (byte) 0x30,
            (byte) 0x10, (byte) 0x82, (byte) 0x0E, (byte) 0x77, (byte) 0x77, (byte) 0x77,
            (byte) 0x2E, (byte) 0x67, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C,
            (byte) 0x65, (byte) 0x2E, (byte) 0x63, (byte) 0x6F, (byte) 0x6D, (byte) 0x30,
            (byte) 0x68, (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01,
            (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x01, (byte) 0x01, (byte) 0x04,
            (byte) 0x5C, (byte) 0x30, (byte) 0x5A, (byte) 0x30, (byte) 0x2B, (byte) 0x06,
            (byte) 0x08, (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05,
            (byte) 0x07, (byte) 0x30, (byte) 0x02, (byte) 0x86, (byte) 0x1F, (byte) 0x68,
            (byte) 0x74, (byte) 0x74, (byte) 0x70, (byte) 0x3A, (byte) 0x2F, (byte) 0x2F,
            (byte) 0x70, (byte) 0x6B, (byte) 0x69, (byte) 0x2E, (byte) 0x67, (byte) 0x6F,
            (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65, (byte) 0x2E, (byte) 0x63,
            (byte) 0x6F, (byte) 0x6D, (byte) 0x2F, (byte) 0x47, (byte) 0x49, (byte) 0x41,
            (byte) 0x47, (byte) 0x32, (byte) 0x2E, (byte) 0x63, (byte) 0x72, (byte) 0x74,
            (byte) 0x30, (byte) 0x2B, (byte) 0x06, (byte) 0x08, (byte) 0x2B, (byte) 0x06,
            (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x30, (byte) 0x01,
            (byte) 0x86, (byte) 0x1F, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x3A, (byte) 0x2F, (byte) 0x2F, (byte) 0x63, (byte) 0x6C, (byte) 0x69,
            (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x73, (byte) 0x31, (byte) 0x2E,
            (byte) 0x67, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65,
            (byte) 0x2E, (byte) 0x63, (byte) 0x6F, (byte) 0x6D, (byte) 0x2F, (byte) 0x6F,
            (byte) 0x63, (byte) 0x73, (byte) 0x70, (byte) 0x30, (byte) 0x1D, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x0E, (byte) 0x04, (byte) 0x16,
            (byte) 0x04, (byte) 0x14, (byte) 0x3B, (byte) 0x6B, (byte) 0xE0, (byte) 0x9C,
            (byte) 0xC6, (byte) 0xC6, (byte) 0x41, (byte) 0xC8, (byte) 0xEA, (byte) 0x5C,
            (byte) 0xFB, (byte) 0x1A, (byte) 0x58, (byte) 0x15, (byte) 0xC2, (byte) 0x1B,
            (byte) 0x9D, (byte) 0x43, (byte) 0x19, (byte) 0x85, (byte) 0x30, (byte) 0x0C,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x13, (byte) 0x01,
            (byte) 0x01, (byte) 0xFF, (byte) 0x04, (byte) 0x02, (byte) 0x30, (byte) 0x00,
            (byte) 0x30, (byte) 0x1F, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D,
            (byte) 0x23, (byte) 0x04, (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x80,
            (byte) 0x14, (byte) 0x4A, (byte) 0xDD, (byte) 0x06, (byte) 0x16, (byte) 0x1B,
            (byte) 0xBC, (byte) 0xF6, (byte) 0x68, (byte) 0xB5, (byte) 0x76, (byte) 0xF5,
            (byte) 0x81, (byte) 0xB6, (byte) 0xBB, (byte) 0x62, (byte) 0x1A, (byte) 0xBA,
            (byte) 0x5A, (byte) 0x81, (byte) 0x2F, (byte) 0x30, (byte) 0x17, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x20, (byte) 0x04, (byte) 0x10,
            (byte) 0x30, (byte) 0x0E, (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x0A,
            (byte) 0x2B, (byte) 0x06, (byte) 0x01, (byte) 0x04, (byte) 0x01, (byte) 0xD6,
            (byte) 0x79, (byte) 0x02, (byte) 0x05, (byte) 0x01, (byte) 0x30, (byte) 0x30,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x1F, (byte) 0x04,
            (byte) 0x29, (byte) 0x30, (byte) 0x27, (byte) 0x30, (byte) 0x25, (byte) 0xA0,
            (byte) 0x23, (byte) 0xA0, (byte) 0x21, (byte) 0x86, (byte) 0x1F, (byte) 0x68,
            (byte) 0x74, (byte) 0x74, (byte) 0x70, (byte) 0x3A, (byte) 0x2F, (byte) 0x2F,
            (byte) 0x70, (byte) 0x6B, (byte) 0x69, (byte) 0x2E, (byte) 0x67, (byte) 0x6F,
            (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65, (byte) 0x2E, (byte) 0x63,
            (byte) 0x6F, (byte) 0x6D, (byte) 0x2F, (byte) 0x47, (byte) 0x49, (byte) 0x41,
            (byte) 0x47, (byte) 0x32, (byte) 0x2E, (byte) 0x63, (byte) 0x72, (byte) 0x6C,
            (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86,
            (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01,
            (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x01,
            (byte) 0x01, (byte) 0x00, (byte) 0x9A, (byte) 0x39, (byte) 0x70, (byte) 0x81,
            (byte) 0x76, (byte) 0x8A, (byte) 0x94, (byte) 0xCB, (byte) 0x96, (byte) 0xF1,
            (byte) 0xCA, (byte) 0xAF, (byte) 0x96, (byte) 0xAE, (byte) 0x1D, (byte) 0x73,
            (byte) 0xB3, (byte) 0x2C, (byte) 0x82, (byte) 0x16, (byte) 0x29, (byte) 0xB5,
            (byte) 0x3C, (byte) 0x7E, (byte) 0x55, (byte) 0x53, (byte) 0x6F, (byte) 0xB2,
            (byte) 0xBC, (byte) 0x34, (byte) 0x96, (byte) 0xAE, (byte) 0x00, (byte) 0xD8,
            (byte) 0xF2, (byte) 0x26, (byte) 0xD1, (byte) 0x18, (byte) 0x99, (byte) 0x9F,
            (byte) 0x7D, (byte) 0xFD, (byte) 0xEB, (byte) 0xE0, (byte) 0xBB, (byte) 0x9D,
            (byte) 0xE6, (byte) 0x46, (byte) 0xA5, (byte) 0x74, (byte) 0xAB, (byte) 0x3D,
            (byte) 0x93, (byte) 0xC6, (byte) 0x25, (byte) 0x28, (byte) 0x3D, (byte) 0xC8,
            (byte) 0x4C, (byte) 0x6E, (byte) 0xCF, (byte) 0xD1, (byte) 0x84, (byte) 0xFF,
            (byte) 0x46, (byte) 0x4F, (byte) 0x21, (byte) 0x2E, (byte) 0x07, (byte) 0xC4,
            (byte) 0xB8, (byte) 0xB7, (byte) 0x2A, (byte) 0xE5, (byte) 0xC7, (byte) 0x34,
            (byte) 0xC6, (byte) 0xA9, (byte) 0x84, (byte) 0xE3, (byte) 0x6C, (byte) 0x49,
            (byte) 0xF8, (byte) 0x4A, (byte) 0x36, (byte) 0xBB, (byte) 0x3A, (byte) 0xBD,
            (byte) 0xAD, (byte) 0x8A, (byte) 0x2B, (byte) 0x73, (byte) 0x97, (byte) 0xA6,
            (byte) 0x30, (byte) 0x2C, (byte) 0x5F, (byte) 0xE4, (byte) 0xBD, (byte) 0x13,
            (byte) 0x24, (byte) 0xE5, (byte) 0xD9, (byte) 0xA8, (byte) 0x74, (byte) 0x29,
            (byte) 0x38, (byte) 0x47, (byte) 0x2E, (byte) 0xA6, (byte) 0xD6, (byte) 0x50,
            (byte) 0xE0, (byte) 0xE8, (byte) 0xDD, (byte) 0x60, (byte) 0xC7, (byte) 0xD2,
            (byte) 0xC6, (byte) 0x4E, (byte) 0x54, (byte) 0xCE, (byte) 0xE7, (byte) 0x94,
            (byte) 0x84, (byte) 0x0D, (byte) 0xE8, (byte) 0x81, (byte) 0x92, (byte) 0x91,
            (byte) 0x71, (byte) 0x19, (byte) 0x1D, (byte) 0x07, (byte) 0x75, (byte) 0x9E,
            (byte) 0x59, (byte) 0x1A, (byte) 0x7E, (byte) 0x9D, (byte) 0x84, (byte) 0x61,
            (byte) 0xC7, (byte) 0x84, (byte) 0xAD, (byte) 0xA3, (byte) 0x6A, (byte) 0xED,
            (byte) 0xD8, (byte) 0x0D, (byte) 0x0C, (byte) 0x2A, (byte) 0x66, (byte) 0x3D,
            (byte) 0xD7, (byte) 0xAE, (byte) 0x46, (byte) 0x1D, (byte) 0x4A, (byte) 0x8C,
            (byte) 0x2B, (byte) 0xD6, (byte) 0x1A, (byte) 0x69, (byte) 0x71, (byte) 0xC3,
            (byte) 0x5E, (byte) 0xA0, (byte) 0x6E, (byte) 0xED, (byte) 0x27, (byte) 0x9F,
            (byte) 0xAF, (byte) 0x5B, (byte) 0x92, (byte) 0xA0, (byte) 0x03, (byte) 0xFD,
            (byte) 0x83, (byte) 0x22, (byte) 0x09, (byte) 0x29, (byte) 0xE8, (byte) 0xA1,
            (byte) 0x32, (byte) 0x2B, (byte) 0xEC, (byte) 0x1A, (byte) 0xA2, (byte) 0x75,
            (byte) 0x4C, (byte) 0x3E, (byte) 0x99, (byte) 0x71, (byte) 0xCE, (byte) 0x8B,
            (byte) 0x31, (byte) 0xEF, (byte) 0x9D, (byte) 0x37, (byte) 0x63, (byte) 0xFC,
            (byte) 0x71, (byte) 0x91, (byte) 0x10, (byte) 0x1E, (byte) 0xD0, (byte) 0xF5,
            (byte) 0xCB, (byte) 0x6F, (byte) 0x7A, (byte) 0xBA, (byte) 0x5E, (byte) 0x0C,
            (byte) 0x8A, (byte) 0xFA, (byte) 0xA4, (byte) 0xDE, (byte) 0x36, (byte) 0xAD,
            (byte) 0x51, (byte) 0x52, (byte) 0xFC, (byte) 0xFE, (byte) 0x10, (byte) 0xB0,
            (byte) 0x81, (byte) 0xC8, (byte) 0x7D, (byte) 0x03, (byte) 0xC3, (byte) 0xB8,
            (byte) 0x3C, (byte) 0x66, (byte) 0x6A, (byte) 0xF5, (byte) 0x6A, (byte) 0x81,
            (byte) 0x7C, (byte) 0x45, (byte) 0xA6, (byte) 0x23, (byte) 0x21, (byte) 0xE1,
            (byte) 0xD5, (byte) 0xD3, (byte) 0xED, (byte) 0x6E, (byte) 0x0D, (byte) 0x65,
            (byte) 0x39, (byte) 0x77, (byte) 0x58, (byte) 0x09, (byte) 0x6B, (byte) 0x63,
            (byte) 0xA4, (byte) 0x02, (byte) 0x04, (byte) 0x00, (byte) 0xA5, (byte) 0x03,
            (byte) 0x02, (byte) 0x01, (byte) 0x14, (byte) 0xA9, (byte) 0x05, (byte) 0x02,
            (byte) 0x03, (byte) 0x01, (byte) 0x89, (byte) 0xC0, (byte) 0xAA, (byte) 0x81,
            (byte) 0xA7, (byte) 0x04, (byte) 0x81, (byte) 0xA4, (byte) 0x1C, (byte) 0x14,
            (byte) 0x42, (byte) 0xFA, (byte) 0x1E, (byte) 0x3A, (byte) 0x4D, (byte) 0x0A,
            (byte) 0x83, (byte) 0x7E, (byte) 0x92, (byte) 0x61, (byte) 0x37, (byte) 0x0B,
            (byte) 0x12, (byte) 0x45, (byte) 0xEA, (byte) 0x2B, (byte) 0x03, (byte) 0x81,
            (byte) 0x7C, (byte) 0x5F, (byte) 0x6F, (byte) 0x13, (byte) 0x82, (byte) 0x97,
            (byte) 0xD0, (byte) 0xDC, (byte) 0x5E, (byte) 0x2F, (byte) 0x08, (byte) 0xDC,
            (byte) 0x0D, (byte) 0x3A, (byte) 0x6C, (byte) 0xBA, (byte) 0x1D, (byte) 0xEA,
            (byte) 0x5C, (byte) 0x46, (byte) 0x99, (byte) 0xF7, (byte) 0xDD, (byte) 0xAB,
            (byte) 0xD4, (byte) 0xDD, (byte) 0xFC, (byte) 0x54, (byte) 0x37, (byte) 0x32,
            (byte) 0x4B, (byte) 0xA3, (byte) 0xFB, (byte) 0x23, (byte) 0xA1, (byte) 0xC1,
            (byte) 0x60, (byte) 0xDF, (byte) 0x41, (byte) 0xB0, (byte) 0xD1, (byte) 0xCC,
            (byte) 0xDF, (byte) 0xAD, (byte) 0xB3, (byte) 0x66, (byte) 0x76, (byte) 0x36,
            (byte) 0xEC, (byte) 0x6A, (byte) 0x53, (byte) 0xC3, (byte) 0xE2, (byte) 0xB0,
            (byte) 0x77, (byte) 0xBE, (byte) 0x75, (byte) 0x08, (byte) 0xBA, (byte) 0x17,
            (byte) 0x14, (byte) 0xFA, (byte) 0x1A, (byte) 0x30, (byte) 0xE7, (byte) 0xB9,
            (byte) 0xED, (byte) 0xD6, (byte) 0xC1, (byte) 0xA5, (byte) 0x7A, (byte) 0x2B,
            (byte) 0xA3, (byte) 0xA3, (byte) 0xDD, (byte) 0xDC, (byte) 0x14, (byte) 0xDB,
            (byte) 0x7F, (byte) 0xF4, (byte) 0xF3, (byte) 0xAF, (byte) 0xCF, (byte) 0x0A,
            (byte) 0xD3, (byte) 0xAC, (byte) 0x84, (byte) 0x39, (byte) 0x30, (byte) 0xCA,
            (byte) 0x3C, (byte) 0xD8, (byte) 0xF7, (byte) 0xFA, (byte) 0x29, (byte) 0xDB,
            (byte) 0x31, (byte) 0xA5, (byte) 0x62, (byte) 0x82, (byte) 0xD2, (byte) 0xB8,
            (byte) 0x3C, (byte) 0xBC, (byte) 0x8F, (byte) 0xAB, (byte) 0xE4, (byte) 0xE8,
            (byte) 0xA7, (byte) 0x2C, (byte) 0xEF, (byte) 0xC7, (byte) 0xD5, (byte) 0x12,
            (byte) 0x16, (byte) 0x04, (byte) 0x6F, (byte) 0xCA, (byte) 0xEA, (byte) 0x31,
            (byte) 0x9F, (byte) 0x41, (byte) 0xE0, (byte) 0x6F, (byte) 0xE4, (byte) 0x74,
            (byte) 0x03, (byte) 0x78, (byte) 0xFA, (byte) 0x48, (byte) 0xB4, (byte) 0x6E,
            (byte) 0xC8, (byte) 0xE7, (byte) 0x40, (byte) 0x8B, (byte) 0x88, (byte) 0x2F,
            (byte) 0xED, (byte) 0x8E, (byte) 0x68, (byte) 0x96, (byte) 0x2C, (byte) 0xA7,
            (byte) 0xB6, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x00};

    private static final byte[] DUMMY_CERT =
            new byte[] {(byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x58, (byte) 0x30,
                    (byte) 0x82, (byte) 0x01, (byte) 0xC1, (byte) 0xA0, (byte) 0x03, (byte) 0x02,
                    (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x09, (byte) 0x00, (byte) 0xFB,
                    (byte) 0xB0, (byte) 0x4C, (byte) 0x2E, (byte) 0xAB, (byte) 0x10, (byte) 0x9B,
                    (byte) 0x0C, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A,
                    (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01,
                    (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x45,
                    (byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03,
                    (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x41,
                    (byte) 0x55, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
                    (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0C, (byte) 0x0A,
                    (byte) 0x53, (byte) 0x6F, (byte) 0x6D, (byte) 0x65, (byte) 0x2D, (byte) 0x53,
                    (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x31, (byte) 0x21,
                    (byte) 0x30, (byte) 0x1F, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
                    (byte) 0x0A, (byte) 0x0C, (byte) 0x18, (byte) 0x49, (byte) 0x6E, (byte) 0x74,
                    (byte) 0x65, (byte) 0x72, (byte) 0x6E, (byte) 0x65, (byte) 0x74, (byte) 0x20,
                    (byte) 0x57, (byte) 0x69, (byte) 0x64, (byte) 0x67, (byte) 0x69, (byte) 0x74,
                    (byte) 0x73, (byte) 0x20, (byte) 0x50, (byte) 0x74, (byte) 0x79, (byte) 0x20,
                    (byte) 0x4C, (byte) 0x74, (byte) 0x64, (byte) 0x30, (byte) 0x1E, (byte) 0x17,
                    (byte) 0x0D, (byte) 0x31, (byte) 0x34, (byte) 0x30, (byte) 0x34, (byte) 0x32,
                    (byte) 0x33, (byte) 0x32, (byte) 0x30, (byte) 0x35, (byte) 0x30, (byte) 0x34,
                    (byte) 0x30, (byte) 0x5A, (byte) 0x17, (byte) 0x0D, (byte) 0x31, (byte) 0x37,
                    (byte) 0x30, (byte) 0x34, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x30,
                    (byte) 0x35, (byte) 0x30, (byte) 0x34, (byte) 0x30, (byte) 0x5A, (byte) 0x30,
                    (byte) 0x45, (byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06,
                    (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02,
                    (byte) 0x41, (byte) 0x55, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11,
                    (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0C,
                    (byte) 0x0A, (byte) 0x53, (byte) 0x6F, (byte) 0x6D, (byte) 0x65, (byte) 0x2D,
                    (byte) 0x53, (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x65, (byte) 0x31,
                    (byte) 0x21, (byte) 0x30, (byte) 0x1F, (byte) 0x06, (byte) 0x03, (byte) 0x55,
                    (byte) 0x04, (byte) 0x0A, (byte) 0x0C, (byte) 0x18, (byte) 0x49, (byte) 0x6E,
                    (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x6E, (byte) 0x65, (byte) 0x74,
                    (byte) 0x20, (byte) 0x57, (byte) 0x69, (byte) 0x64, (byte) 0x67, (byte) 0x69,
                    (byte) 0x74, (byte) 0x73, (byte) 0x20, (byte) 0x50, (byte) 0x74, (byte) 0x79,
                    (byte) 0x20, (byte) 0x4C, (byte) 0x74, (byte) 0x64, (byte) 0x30, (byte) 0x81,
                    (byte) 0x9F, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A,
                    (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01,
                    (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x81,
                    (byte) 0x8D, (byte) 0x00, (byte) 0x30, (byte) 0x81, (byte) 0x89, (byte) 0x02,
                    (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0xD8, (byte) 0x2B, (byte) 0xC8,
                    (byte) 0xA6, (byte) 0x32, (byte) 0xE4, (byte) 0x62, (byte) 0xFF, (byte) 0x4D,
                    (byte) 0xF3, (byte) 0xD0, (byte) 0xAD, (byte) 0x59, (byte) 0x8B, (byte) 0x45,
                    (byte) 0xA7, (byte) 0xBD, (byte) 0xF1, (byte) 0x47, (byte) 0xBF, (byte) 0x09,
                    (byte) 0x58, (byte) 0x7B, (byte) 0x22, (byte) 0xBD, (byte) 0x35, (byte) 0xAE,
                    (byte) 0x97, (byte) 0x25, (byte) 0x86, (byte) 0x94, (byte) 0xA0, (byte) 0x80,
                    (byte) 0xC0, (byte) 0xB4, (byte) 0x1F, (byte) 0x76, (byte) 0x91, (byte) 0x67,
                    (byte) 0x46, (byte) 0x31, (byte) 0xD0, (byte) 0x10, (byte) 0x84, (byte) 0xB7,
                    (byte) 0x22, (byte) 0x1E, (byte) 0x70, (byte) 0x23, (byte) 0x91, (byte) 0x72,
                    (byte) 0xC8, (byte) 0xE9, (byte) 0x6D, (byte) 0x79, (byte) 0x3A, (byte) 0x85,
                    (byte) 0x77, (byte) 0x80, (byte) 0x0F, (byte) 0xC4, (byte) 0x95, (byte) 0x16,
                    (byte) 0x75, (byte) 0xC5, (byte) 0x4A, (byte) 0x71, (byte) 0x4C, (byte) 0xC8,
                    (byte) 0x63, (byte) 0x3F, (byte) 0xA3, (byte) 0xF2, (byte) 0x63, (byte) 0x9C,
                    (byte) 0x2A, (byte) 0x4F, (byte) 0x9A, (byte) 0xFA, (byte) 0xCB, (byte) 0xC1,
                    (byte) 0x71, (byte) 0x6E, (byte) 0x28, (byte) 0x85, (byte) 0x28, (byte) 0xA0,
                    (byte) 0x27, (byte) 0x1E, (byte) 0x65, (byte) 0x1C, (byte) 0xAE, (byte) 0x07,
                    (byte) 0xD5, (byte) 0x5B, (byte) 0x6F, (byte) 0x2D, (byte) 0x43, (byte) 0xED,
                    (byte) 0x2B, (byte) 0x90, (byte) 0xB1, (byte) 0x8C, (byte) 0xAF, (byte) 0x24,
                    (byte) 0x6D, (byte) 0xAE, (byte) 0xE9, (byte) 0x17, (byte) 0x3A, (byte) 0x05,
                    (byte) 0xC1, (byte) 0xBF, (byte) 0xB8, (byte) 0x1C, (byte) 0xAE, (byte) 0x65,
                    (byte) 0x3B, (byte) 0x1B, (byte) 0x58, (byte) 0xC2, (byte) 0xD9, (byte) 0xAE,
                    (byte) 0xD6, (byte) 0xAA, (byte) 0x67, (byte) 0x88, (byte) 0xF1, (byte) 0x02,
                    (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xA3, (byte) 0x50,
                    (byte) 0x30, (byte) 0x4E, (byte) 0x30, (byte) 0x1D, (byte) 0x06, (byte) 0x03,
                    (byte) 0x55, (byte) 0x1D, (byte) 0x0E, (byte) 0x04, (byte) 0x16, (byte) 0x04,
                    (byte) 0x14, (byte) 0x8B, (byte) 0x75, (byte) 0xD5, (byte) 0xAC, (byte) 0xCB,
                    (byte) 0x08, (byte) 0xBE, (byte) 0x0E, (byte) 0x1F, (byte) 0x65, (byte) 0xB7,
                    (byte) 0xFA, (byte) 0x56, (byte) 0xBE, (byte) 0x6C, (byte) 0xA7, (byte) 0x75,
                    (byte) 0xDA, (byte) 0x85, (byte) 0xAF, (byte) 0x30, (byte) 0x1F, (byte) 0x06,
                    (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x23, (byte) 0x04, (byte) 0x18,
                    (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14, (byte) 0x8B, (byte) 0x75,
                    (byte) 0xD5, (byte) 0xAC, (byte) 0xCB, (byte) 0x08, (byte) 0xBE, (byte) 0x0E,
                    (byte) 0x1F, (byte) 0x65, (byte) 0xB7, (byte) 0xFA, (byte) 0x56, (byte) 0xBE,
                    (byte) 0x6C, (byte) 0xA7, (byte) 0x75, (byte) 0xDA, (byte) 0x85, (byte) 0xAF,
                    (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D,
                    (byte) 0x13, (byte) 0x04, (byte) 0x05, (byte) 0x30, (byte) 0x03, (byte) 0x01,
                    (byte) 0x01, (byte) 0xFF, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09,
                    (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D,
                    (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x03,
                    (byte) 0x81, (byte) 0x81, (byte) 0x00, (byte) 0x3B, (byte) 0xE8, (byte) 0x78,
                    (byte) 0x6D, (byte) 0x95, (byte) 0xD6, (byte) 0x3D, (byte) 0x6A, (byte) 0xF7,
                    (byte) 0x13, (byte) 0x19, (byte) 0x2C, (byte) 0x1B, (byte) 0xC2, (byte) 0x88,
                    (byte) 0xAE, (byte) 0x22, (byte) 0xAB, (byte) 0xF4, (byte) 0x8D, (byte) 0x32,
                    (byte) 0xF5, (byte) 0x7C, (byte) 0x71, (byte) 0x67, (byte) 0xCF, (byte) 0x2D,
                    (byte) 0xD1, (byte) 0x1C, (byte) 0xC2, (byte) 0xC3, (byte) 0x87, (byte) 0xE2,
                    (byte) 0xE9, (byte) 0xBE, (byte) 0x89, (byte) 0x5C, (byte) 0xE4, (byte) 0x34,
                    (byte) 0xAB, (byte) 0x48, (byte) 0x91, (byte) 0xC2, (byte) 0x3F, (byte) 0x95,
                    (byte) 0xAE, (byte) 0x2B, (byte) 0x47, (byte) 0x9E, (byte) 0x25, (byte) 0x78,
                    (byte) 0x6B, (byte) 0x4F, (byte) 0x9A, (byte) 0x10, (byte) 0xA4, (byte) 0x72,
                    (byte) 0xFD, (byte) 0xCF, (byte) 0xF7, (byte) 0x02, (byte) 0x0C, (byte) 0xB0,
                    (byte) 0x0A, (byte) 0x08, (byte) 0xA4, (byte) 0x5A, (byte) 0xE2, (byte) 0xE5,
                    (byte) 0x74, (byte) 0x7E, (byte) 0x11, (byte) 0x1D, (byte) 0x39, (byte) 0x60,
                    (byte) 0x6A, (byte) 0xC9, (byte) 0x1F, (byte) 0x69, (byte) 0xF3, (byte) 0x2E,
                    (byte) 0x63, (byte) 0x26, (byte) 0xDC, (byte) 0x9E, (byte) 0xEF, (byte) 0x6B,
                    (byte) 0x7A, (byte) 0x0A, (byte) 0xE1, (byte) 0x54, (byte) 0x57, (byte) 0x98,
                    (byte) 0xAA, (byte) 0x72, (byte) 0x91, (byte) 0x78, (byte) 0x04, (byte) 0x7E,
                    (byte) 0x1F, (byte) 0x8F, (byte) 0x65, (byte) 0x4D, (byte) 0x1F, (byte) 0x0B,
                    (byte) 0x12, (byte) 0xAC, (byte) 0x9C, (byte) 0x24, (byte) 0x0F, (byte) 0x84,
                    (byte) 0x14, (byte) 0x1A, (byte) 0x55, (byte) 0x2D, (byte) 0x1F, (byte) 0xBB,
                    (byte) 0xF0, (byte) 0x9D, (byte) 0x09, (byte) 0xB2, (byte) 0x08, (byte) 0x5C,
                    (byte) 0x59, (byte) 0x32, (byte) 0x65, (byte) 0x80, (byte) 0x26};

    private static final byte[] DUMMY_OCSP_DATA = new byte[1];

    private static final byte[] DUMMY_TLS_SCT_DATA = new byte[1];

    @After
    public void tearDown() throws Exception {
        assertEquals(0, NativeCrypto.ERR_peek_last_error());
    }

    private static TestSessionBuilder getType1() {
        return new TestSessionBuilder()
                .setType(0x01)
                .setSessionData(kOpenSSLSession)
                .addCertificate(DUMMY_CERT);
    }

    private static TestSessionBuilder getType2() {
        return new TestSessionBuilder()
                .setType(0x02)
                .setSessionData(kOpenSSLSession)
                .addCertificate(DUMMY_CERT)
                .addOcspData(DUMMY_OCSP_DATA);
    }

    private static TestSessionBuilder getType3() {
        return new TestSessionBuilder()
                .setType(0x03)
                .setSessionData(kOpenSSLSession)
                .addCertificate(DUMMY_CERT)
                .addOcspData(DUMMY_OCSP_DATA)
                .setTlsSctData(DUMMY_TLS_SCT_DATA);
    }

    @Test
    public void toSession_EmptyArray_Invalid_Failure() throws Exception {
        assertInvalidSession(new byte[0]);
    }

    @Test
    public void toSession_Type1_Valid_Success() throws Exception {
        assertValidSession(getType1().build());
    }

    @Test
    public void toSession_Type2_Valid_Success() throws Exception {
        assertValidSession(getType2().build());
    }

    @Test
    public void toSession_Type3_Valid_Success() throws Exception {
        assertValidSession(getType3().build());
    }

    private void assertTruncatedSessionFails(byte[] validSession) {
        for (int i = 0; i < validSession.length - 1; i++) {
            byte[] truncatedSession = new byte[i];
            System.arraycopy(validSession, 0, truncatedSession, 0, i);
            assertNull("Truncating to " + i + " bytes of " + validSession.length
                            + " should not succeed",
                    SslSessionWrapper.newInstance(null, truncatedSession, "www.google.com", 443));
        }
    }

    @Test
    public void toSession_Type3_Truncated_Failure() throws Exception {
        assertTruncatedSessionFails(getType3().build());
    }

    private static void assertValidSession(byte[] data) {
        assertNotNull(SslSessionWrapper.newInstance(null, data, "www.google.com", 443));
    }

    private static void assertInvalidSession(byte[] data) {
        assertNull(SslSessionWrapper.newInstance(null, data, "www.google.com", 443));
    }

    @Test
    public void toSession_UnknownType_Failure() throws Exception {
        assertInvalidSession(getType3().setType((byte) 0xEE).build());
    }

    @Test
    public void toSession_CertificatesCountTooLarge_Failure() throws Exception {
        assertInvalidSession(getType3().setCertificatesLength(16834).build());
    }

    @Test
    public void toSession_CertificatesCountNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setCertificatesLength(-1).build());
    }

    @Test
    public void toSession_CertificateSizeNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setCertificateLength(0, -1).build());
    }

    @Test
    public void toSession_CertificateSizeTooLarge_Failure() throws Exception {
        assertInvalidSession(getType3().setCertificateLength(0, 16834).build());
    }

    @Test
    public void toSession_SessionDataSizeTooLarge_Failure() throws Exception {
        assertInvalidSession(getType3().setSessionDataLength(16834).build());
    }

    @Test
    public void toSession_SessionDataSizeNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setSessionDataLength(-1).build());
    }

    @Test
    public void toSession_OcspDatasNumberTooMany_Failure() throws Exception {
        assertInvalidSession(getType3().setOcspDatasLength(32791).build());
    }

    @Test
    public void toSession_OcspDatasNumberNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setOcspDatasLength(-1).build());
    }

    @Test
    public void toSession_OcspDataSizeNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setOcspDataLength(0, -1).build());
    }

    @Test
    public void toSession_OcspDataSizeTooLarge_Failure() throws Exception {
        assertInvalidSession(getType3().setOcspDataLength(0, 92948).build());
    }

    @Test
    public void toSession_TlsSctDataSizeNegative_Failure() throws Exception {
        assertInvalidSession(getType3().setTlsSctDataLength(-1).build());
    }

    @Test
    public void toSession_TlsSctDataSizeTooLarge_Failure() throws Exception {
        assertInvalidSession(getType3().setTlsSctDataLength(931148).build());
    }

    @Test
    public void toSession_Type2OcspDataEmpty_Success() throws Exception {
        assertValidSession(getType1().setType(0x02).setOcspDataEmpty().build());
    }

    @Test
    public void toSession_Type3TlsSctDataEmpty_Success() throws Exception {
        assertValidSession(getType2().setType(0x03).setTlsSctDataEmpty().build());
    }

    @Test
    public void toSession_Type3OcspAndTlsSctDataEmpty_Success() throws Exception {
        assertValidSession(
                getType1().setType(0x03).setOcspDataEmpty().setTlsSctDataEmpty().build());
    }

    private static void assertTrailingDataFails(byte[] validSession) {
        byte[] invalidSession = new byte[validSession.length + 1];
        System.arraycopy(validSession, 0, invalidSession, 0, validSession.length);
        assertInvalidSession(invalidSession);
    }

    @Test
    public void toSession_Type1TrailingData_Failure() throws Exception {
        assertTrailingDataFails(getType1().build());
    }

    @Test
    public void toSession_Type2TrailingData_Failure() throws Exception {
        assertTrailingDataFails(getType2().build());
    }

    @Test
    public void toSession_Type3TrailingData_Failure() throws Exception {
        assertTrailingDataFails(getType3().build());
    }

    @Test
    public void test_reserializableFromByteArray_roundTrip_type1() throws Exception {
        // Converting OPEN_SSL (type 1) -> OPEN_SSL_WITH_TLS_SCT (type 3) adds
        // eight zero-bytes:
        //  1.) 4 bytes for int32 value 0 == countOcspResponses
        //  2.) 4 bytes for int32 value 0 == tlsSctDataLength
        // since OPEN_SSL (type 1) cannot contain OSCP or TLS SCT data.
        check_reserializableFromByteArray_roundTrip(getType1().build(), new byte[8]);
    }

    @Test
    public void test_reserializableFromByteArray_roundTrip_type2() throws Exception {
        // Converting OPEN_SSL_WITH_OCSP (type 2) -> OPEN_SSL_WITH_TLS_SCT (type 3) adds
        // four zero-bytes for int32 value 0 == tlsSctDataLength
        // since OPEN_SSL_WITH_OCSP (type 2) cannot contain TLS SCT data.
        check_reserializableFromByteArray_roundTrip(getType2().build(), new byte[4]);
    }

    @Test
    public void test_reserializableFromByteArray_roundTrip_type3() throws Exception {
        check_reserializableFromByteArray_roundTrip(getType3().build(), new byte[0]);
    }

    private static void check_reserializableFromByteArray_roundTrip(
            byte[] data, byte[] expectedTrailingBytesAfterReserialization) throws Exception {
        SslSessionWrapper session =
                SslSessionWrapper.newInstance(null, data, "www.example.com", 12345);
        byte[] sessionBytes = session.toBytes();

        SslSessionWrapper session2 =
                SslSessionWrapper.newInstance(null, sessionBytes, "www.example.com", 12345);
        byte[] sessionBytes2 = session2.toBytes();

        assertSSLSessionEquals(session, session2);
        assertByteArrayEquals(sessionBytes, sessionBytes2);

        assertEquals("www.example.com", session.getPeerHost());
        assertEquals(12345, session.getPeerPort());
        assertTrue(sessionBytes.length >= data.length);

        byte[] expectedReserializedData = concat(data, expectedTrailingBytesAfterReserialization);
        // AbstractSessionContext.toBytes() always writes type 3 == OPEN_SSL_WITH_TLS_SCT
        expectedReserializedData[3] = 3;
        assertByteArrayEquals(expectedReserializedData, sessionBytes);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static void assertSSLSessionEquals(SslSessionWrapper a, SslSessionWrapper b)
            throws Exception {
        assertEquals(a.getCipherSuite(), b.getCipherSuite());
        assertByteArrayEquals(a.getId(), b.getId());
        assertEquals(a.getPeerHost(), b.getPeerHost());
        assertEquals(a.getPeerPort(), b.getPeerPort());
        assertEquals(a.getProtocol(), b.getProtocol());
    }

    private static void assertByteArrayEquals(byte[] expected, byte[] actual) {
        // If running on OpenJDK 8+, could use java.util.Base64 for better failure messages:
        // assertEquals(Base64.encode(expected), Base64.encode(actual));
        assertTrue("Expected " + Arrays.toString(expected) + ", got " + Arrays.toString(actual),
                Arrays.equals(expected, actual));
    }
}
