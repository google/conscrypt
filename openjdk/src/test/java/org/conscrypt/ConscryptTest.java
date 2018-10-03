package org.conscrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ConscryptTest {

    /**
     * This confirms that the version machinery is working.
     */
    @Test
    public void testVersionIsSensible() {
        Conscrypt.Version version = Conscrypt.version();
        assertNotNull(version);
        // The version object should be a singleton
        assertSame(version, Conscrypt.version());

        assertEquals("Major version: " + version.major(), 1, version.major());
        assertTrue("Minor version: " + version.minor(), 0 <= version.minor());
        assertTrue("Patch version: " + version.patch(), 0 <= version.patch());
    }
}
