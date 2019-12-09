package org.conscrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MoreAssertions {
  public static void assertContentsEqual(Collection<?> expected, Collection<?> actual) {
    assertContentsEqual(null, expected, actual);
  }

  public static void assertContentsEqual(
      String message, Collection<?> expected, Collection<?> actual) {
    assertEquals(message, expected.size(), actual.size());
    assertTrue(message, actual.containsAll(expected));
    List<Object> elements = new ArrayList<>(actual);
    elements.removeAll(expected);
    assertEquals(message, 0, elements.size());
  }
}
