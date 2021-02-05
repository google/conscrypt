package org.conscrypt.metrics;

import static org.junit.Assert.assertSame;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CipherSuiteTest {

    @Test
    public void consistency() {
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            assertSame(cipherSuite, CipherSuite.forName(cipherSuite.name()));
        }
        assertSame(CipherSuite.UNKNOWN_CIPHER_SUITE, CipherSuite.forName("random junk"));
    }
}
