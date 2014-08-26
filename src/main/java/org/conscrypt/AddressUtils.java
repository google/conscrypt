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

/**
 * Utilities to check whether IP addresses meet some criteria.
 */
public final class AddressUtils {
    private AddressUtils() {
    }

    /**
     * Returns true when the supplied hostname is valid for SNI purposes.
     */
    public static boolean isValidSniHostname(String sniHostname) {
        if (sniHostname == null) {
            return false;
        }

        // Must be a FQDN.
        if (sniHostname.indexOf('.') == -1) {
            return false;
        }

        if (Platform.isLiteralIpAddress(sniHostname)) {
            return false;
        }

        return true;
    }

}
