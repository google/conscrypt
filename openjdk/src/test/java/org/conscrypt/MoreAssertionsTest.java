/*
 * Copyright (C) 2019 The Android Open Source Project
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
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class MoreAssertionsTest {
  private static List<Integer> listOf(Integer... ints) {
    return Arrays.asList(ints);
  }

  private static Set<Integer> setOf(Integer... ints) {
    return new HashSet<>(Arrays.asList(ints));
  }

  @Test
  public void contentsEqual() {
    MoreAssertions.assertContentsEqual(
        listOf(1, 2, 3, 4),
        listOf(1, 2, 3, 4));
    MoreAssertions.assertContentsEqual(
        listOf(1, 2, 3, 4),
        setOf(1, 2, 3, 4));
    MoreAssertions.assertContentsEqual(
        listOf(1, 2, 3, 4),
        setOf(1, 2, 3, 4, 4));
    MoreAssertions.assertContentsEqual(
        listOf(4, 3, 2, 1),
        listOf(1, 2, 3, 4));
    MoreAssertions.assertContentsEqual(
        listOf(1, 1, 2, 2, 3, 3, 4, 4),
        listOf(1, 2, 3, 4, 1, 2, 3, 4));
    MoreAssertions.assertContentsEqual(
        listOf(),
        listOf());
  }

  @Test
  public void contentsNotEqual() {
    assertComparisonFails(
        listOf(1, 2, 3, 4),
        listOf(1, 2, 3, 5)
    );
    assertComparisonFailsWithMessage("Failure Message",
        listOf(1, 2, 3, 4),
        listOf(1, 2, 3, 5)
    );
    assertComparisonFails(
        listOf(1, 2, 3, 4),
        listOf(1, 2, 3, 5)
    );
    assertComparisonFails(
        listOf(1, 2, 3, 3, 4),
        listOf(1, 2, 3, 4)
    );
    assertComparisonFails(
        listOf(1, 2, 3, 3, 4),
        setOf(1, 2, 3, 3, 4)
    );
    assertComparisonFails(
        listOf(1, 2, 3, 4),
        listOf(1, 2, 3, 3, 4)
    );
    assertComparisonFails(
        listOf(1),
        listOf());
    assertComparisonFails(
        listOf(),
        listOf(1));
  }

  private void assertComparisonFails(Collection<?> expected, Collection<?> actual) {
    boolean pass = false;
    try {
      MoreAssertions.assertContentsEqual(expected, actual);
    } catch (AssertionError e) {
      pass = true;
    }
    assertTrue("Collections should not be equal: <" + expected + "> and <" + actual +">", pass);
  }

  private void assertComparisonFailsWithMessage(
      String expectedMessage, Collection<?> expected, Collection<?> actual) {
    String message = null;
    try {
      MoreAssertions.assertContentsEqual(expectedMessage, expected, actual);
    } catch (AssertionError e) {
      message = e.getMessage();
    }
    assertEquals(expectedMessage, message);
  }
}
