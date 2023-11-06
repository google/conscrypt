/*
 * Copyright 2017 The Android Open Source Project
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

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.when;

import java.nio.charset.Charset;
import javax.net.ssl.SSLEngine;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class ApplicationProtocolSelectorAdapterTest {
    private static Charset US_ASCII = Charset.forName("US-ASCII");
    private static final String[] PROTOCOLS = new String[] {"a", "b", "c"};
    private static final byte[] PROTOCOL_BYTES = SSLUtils.encodeProtocols(PROTOCOLS);

    @Mock private ApplicationProtocolSelector selector;

    @Mock private SSLEngine engine;

    private ApplicationProtocolSelectorAdapter adapter;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);

        adapter = new ApplicationProtocolSelectorAdapter(engine, selector);
    }

    @Test
    public void nullProtocolsShouldNotSelect() {
        mockSelection("a");
        assertEquals(-1, select(null));
    }

    @Test
    public void emptyProtocolsShouldNotSelect() {
        mockSelection("a");
        assertEquals(-1, select(EmptyArray.BYTE));
    }

    @Test
    public void selectCorrectProtocol() {
        for (String protocol : PROTOCOLS) {
            mockSelection(protocol);
            assertEquals(protocol, getProtocolAt(select(PROTOCOL_BYTES)));
        }
    }

    @Test
    public void invalidProtocolShouldNotSelect() {
        mockSelection("d");
        assertEquals(-1, select(PROTOCOL_BYTES));
    }

    private int select(byte[] protocols) {
        return adapter.selectApplicationProtocol(protocols);
    }

    private void mockSelection(String returnValue) {
        when(selector.selectApplicationProtocol(same(engine), ArgumentMatchers.<String>anyList()))
                .thenReturn(returnValue);
    }

    private String getProtocolAt(int index) {
        int len = PROTOCOL_BYTES[index];
        return new String(PROTOCOL_BYTES, index + 1, len, US_ASCII);
    }
}
