/*
 * Copyright 2014 The Android Open Source Project
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

/** Utilities to check whether IP addresses meet some criteria. */
final class AddressUtils {

    private static final int IPV4_OCTET_COUNT = 4;
    private static final int MAX_IPV4_OCTET_VALUE = 255;
    private static final int MAX_IPV4_OCTET_DIGITS = 3;
    private static final int MAX_IPV4_DOTS = IPV4_OCTET_COUNT - 1;
    private static final int MIN_IPV4_ADDRESS_LENGTH = 7;
    private static final int MAX_IPV4_ADDRESS_LENGTH = 15;

    private static final int IPV6_TOTAL_GROUPS = 8;
    private static final int IPV6_GROUPS_PER_IPV4 = 2;
    private static final int MAX_HEX_DIGITS_PER_GROUP = 4;

    private static final int ASCII_CASE_DIFF = 'a' - 'A';

    private AddressUtils() {}

    /** Returns true when the supplied hostname is valid for SNI purposes. */
    static boolean isValidSniHostname(String sniHostname) {
        if (sniHostname == null) {
            return false;
        }

        // Must be a FQDN that does not have a trailing dot.
        return (asciiEqualsIgnoreCase(sniHostname, "localhost") || sniHostname.indexOf('.') != -1)
                && !isLiteralIpAddress(sniHostname)
                && !sniHostname.endsWith(".")
                && sniHostname.indexOf('\0') == -1;
    }

    /** Returns true if the supplied hostname is an literal IP address. */
    static boolean isLiteralIpAddress(String hostname) {
        if (hostname.isEmpty()) {
            return false;
        }
        return isValidIPv4(hostname, 0, hostname.length(), /* allowLeadingZeros= */ true)
                || isValidIPv6(hostname);
    }

    /**
     * Validates IPv4 address. Expects exactly 4 octets separated by dots, each octet being 0-255.
     * Allows leading zeros (up to 3 digits per octet). Parses the substring [start, end) without
     * allocation.
     */
    private static boolean isValidIPv4(String s, int start, int end, boolean allowLeadingZeros) {
        int len = end - start;
        if (len < MIN_IPV4_ADDRESS_LENGTH || len > MAX_IPV4_ADDRESS_LENGTH) {
            return false;
        }
        int octets = 0;
        int value = 0;
        int partLen = 0;
        for (int i = start; i < end; i++) {
            char c = s.charAt(i);
            if (c == '.') {
                octets++;
                if (partLen == 0 || octets > MAX_IPV4_DOTS) {
                    return false;
                }
                value = 0;
                partLen = 0;
            } else if (isDigit(c)) {
                if (!allowLeadingZeros && partLen == 1 && value == 0) {
                    return false;
                }
                value = value * 10 + (c - '0');
                partLen++;
                if (partLen > MAX_IPV4_OCTET_DIGITS || value > MAX_IPV4_OCTET_VALUE) {
                    return false;
                }
            } else {
                return false;
            }
        }
        octets++;
        return octets == IPV4_OCTET_COUNT && partLen > 0;
    }

    /**
     * Validates IPv6 address. Supports full, compressed (::), and embedded IPv4 formats. Also
     * supports optional Zone ID (%zone) at the end. Scans the string in a single pass without
     * allocations.
     */
    private static boolean isValidIPv6(String s) {
        if (s.indexOf(':') == -1) {
            return false;
        }
        int len = s.length();
        int groupCount = 0;
        int groupLen = 0;
        boolean hasDoubleColon = false;
        int groupStart = 0;

        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);

            if (c == ':') {
                boolean isDoubleColon = (i + 1 < len && s.charAt(i + 1) == ':');
                if (isDoubleColon) {
                    if (hasDoubleColon) {
                        return false; // Multiple "::"
                    }
                    hasDoubleColon = true;
                    i++; // Skip second colon

                    // Check for triple colon ":::"
                    if (i + 1 < len && s.charAt(i + 1) == ':') {
                        return false;
                    }

                    if (groupLen > 0) {
                        groupCount++;
                        if (groupCount >= IPV6_TOTAL_GROUPS) {
                            return false;
                        }
                    }
                    groupLen = 0;
                    groupStart = i + 1;
                } else {
                    // Single colon validation
                    if (i == len - 1 || s.charAt(i + 1) == '%' || groupLen == 0) {
                        return false;
                    }
                    groupCount++;
                    if (groupCount > IPV6_TOTAL_GROUPS
                            || (hasDoubleColon && groupCount >= IPV6_TOTAL_GROUPS)) {
                        return false;
                    }
                    groupLen = 0;
                    groupStart = i + 1;
                }
            } else if (c == '.') {
                // Embedded IPv4 detected. Find the end of it (either end of string or start of zone
                // ID '%').
                int ipv4End = i;
                while (ipv4End < len && s.charAt(ipv4End) != '%') {
                    ipv4End++;
                }
                // Validate optional Zone ID if present after IPv4
                if (ipv4End < len && !isValidZoneId(s, ipv4End + 1)) {
                    return false;
                }

                if (!isValidIPv4(s, groupStart, ipv4End, /* allowLeadingZeros= */ false)) {
                    return false;
                }
                groupCount += IPV6_GROUPS_PER_IPV4;
                groupLen = 0;
                break; // We have consumed the rest of the IP (and validated zone ID if present)
            } else if (c == '%') {
                // Standard IPv6 Zone ID
                if (!isValidZoneId(s, i + 1)) {
                    return false;
                }
                if (groupLen > 0) {
                    groupCount++;
                }
                groupLen = 0;
                break; // Exit loop, zone ID is validated
            } else {
                if (!isHexDigit(c)) {
                    return false;
                }
                groupLen++;
                if (groupLen > MAX_HEX_DIGITS_PER_GROUP) {
                    return false;
                }
            }
        }

        if (groupLen > 0) {
            groupCount++;
        }

        return hasDoubleColon ? groupCount < IPV6_TOTAL_GROUPS : groupCount == IPV6_TOTAL_GROUPS;
    }

    /**
     * Validates the IPv6 Zone ID (Scope ID). A valid Zone ID must not be empty and must not contain
     * any line terminators, matching the behavior of the '.' character in the original regular
     * expression.
     */
    private static boolean isValidZoneId(String s, int start) {
        int len = s.length();
        if (start >= len) {
            return false;
        }
        for (int i = start; i < len; i++) {
            char c = s.charAt(i);
            // Reject Unicode line terminators.
            // In addition to the standard Java line terminators (\n, \r, \u0085, \u2028, \u2029),
            // we also reject Vertical Tab (\u000B) and Form Feed (\u000C).
            //
            // This is because the old regex implementation relied on the '.' character, which
            // matches anything except line terminators.
            // - On Android, the ICU regex engine treats \u000B and \u000C as line terminators,
            //   so the old implementation rejected them.
            // - On OpenJDK, the JDK regex engine does NOT treat them as line terminators,
            //   so the old implementation allowed them.
            //
            // We choose to reject them consistently on all platforms because they are control
            // characters and are not valid in a real network interface name (Zone ID).
            if (c == '\n'
                    || c == '\r'
                    || c == '\u0085'
                    || c == '\u2028'
                    || c == '\u2029'
                    || c == '\u000B'
                    || c == '\u000C') {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns true if the character is a basic ASCII digit (0-9). We use this custom implementation
     * instead of {@link Character#isDigit(char)} to avoid checking for other Unicode digit
     * characters, keeping it strictly to ASCII and avoiding any locale or Unicode overhead.
     */
    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /**
     * Returns true if the character is a valid hexadecimal digit (0-9, a-f, A-F). This is a simple
     * range check that avoids any character class or regex compilation.
     */
    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static char toLowerCaseAscii(char c) {
        if (c >= 'A' && c <= 'Z') {
            return (char) (c + ASCII_CASE_DIFF);
        }
        return c;
    }

    /**
     * Compares two ASCII strings case-insensitively. We use this custom implementation instead of
     * {@link String#equalsIgnoreCase(String)} to: 1. Avoid dependency on Guava's Ascii class. 2.
     * Avoid locale-dependent behavior of String.equalsIgnoreCase (e.g. Turkish 'I' mapping),
     * ensuring strictly ASCII comparison. 3. Avoid any object allocations.
     */
    private static boolean asciiEqualsIgnoreCase(String s, String expected) {
        int len = s.length();
        if (len != expected.length()) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            char c1 = s.charAt(i);
            char c2 = expected.charAt(i);
            if (c1 != c2 && toLowerCaseAscii(c1) != toLowerCaseAscii(c2)) {
                return false;
            }
        }
        return true;
    }
}
