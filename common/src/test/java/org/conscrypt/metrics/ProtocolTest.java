package org.conscrypt.metrics;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertSame;

@RunWith(JUnit4.class)
public class ProtocolTest {
    @Test
    public void consistency() {
        for (Protocol protocol : Protocol.values()) {
            String name = protocol.name().replace('_', '.');
            assertSame(protocol, Protocol.forName(name));
        }
    }
}
