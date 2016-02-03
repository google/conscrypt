/*
 * Copyright 2016 The Android Open Source Project
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

package javax.net.ssl;

import java.util.List;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLSession;

/**
 * This is a stub class used for compiling against.
 */
public abstract class ExtendedSSLSession implements SSLSession {

    public ExtendedSSLSession() {
    }

    public abstract String[] getLocalSupportedSignatureAlgorithms();

    public abstract String[] getPeerSupportedSignatureAlgorithms();

    public List<SNIServerName> getRequestedServerNames() {
        return null;
    }
}
