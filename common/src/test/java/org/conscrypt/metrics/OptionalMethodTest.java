package org.conscrypt.metrics;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(JUnit4.class)
public class OptionalMethodTest {

    @Test
    public void workingMethod() {
        OptionalMethod substring =
                new OptionalMethod(String.class, "substring", int.class, int.class);
        assertNotNull(substring);

        String input = "thermostats";
        String result = (String) substring.invoke(input, 6, 10);
        assertEquals("stat", result);

    }

    @Test
    public void nullClass() {
        OptionalMethod substring =
                new OptionalMethod(null, "substring", int.class, int.class);
        assertNotNull(substring);

        String input = "thermostats";
        String result = (String) substring.invoke(input, 6, 10);
        assertNull(result);
    }

    @Test(expected = NullPointerException.class)
    public void nullMethodName() {
        new OptionalMethod(String.class, null, int.class, int.class);
    }

    @Test(expected =  NullPointerException.class)
    public void nullArgumentClasses() {
        new OptionalMethod(String.class, "substring", null, null);
    }

    @Test
    public void noSuchMethodName() {
        OptionalMethod subwrong =
                new OptionalMethod(null, "subwrong", int.class, int.class);
        assertNotNull(subwrong);

        String input = "input";
        assertNull(subwrong.invoke(input, 1, 3));
    }

    @Test
    public void noSuchMethodArgs() {
        OptionalMethod subwrong =
                new OptionalMethod(null, "substring", long.class, byte[].class);
        assertNotNull(subwrong);

        String input = "input";
        assertNull(subwrong.invoke(input, 1, 3));
    }
}
