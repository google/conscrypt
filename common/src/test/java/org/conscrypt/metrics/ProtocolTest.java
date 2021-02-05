package org.conscrypt.metrics;

import static org.junit.Assert.assertSame;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

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
