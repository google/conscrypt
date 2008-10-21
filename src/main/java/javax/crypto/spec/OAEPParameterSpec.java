/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
* @author Alexander Y. Kleymenov
* @version $Revision$
*/

package javax.crypto.spec;

import java.security.spec.MGF1ParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.PSource;

/**
 * @com.intel.drl.spec_ref
 */
public class OAEPParameterSpec implements AlgorithmParameterSpec {

    private final String mdName;
    private final String mgfName;
    private final AlgorithmParameterSpec mgfSpec;
    private final PSource pSrc;

    /**
     * @com.intel.drl.spec_ref
     */
    public static final OAEPParameterSpec DEFAULT = new OAEPParameterSpec();

    private OAEPParameterSpec() {
        this.mdName = "SHA-1"; //$NON-NLS-1$
        this.mgfName = "MGF1"; //$NON-NLS-1$
        this.mgfSpec = MGF1ParameterSpec.SHA1;
        this.pSrc = PSource.PSpecified.DEFAULT;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public OAEPParameterSpec(String mdName, String mgfName,
                                AlgorithmParameterSpec mgfSpec, PSource pSrc) {
        if ((mdName == null) || (mgfName == null) || (pSrc == null)) {
            throw new NullPointerException();
        }
        this.mdName = mdName;
        this.mgfName = mgfName;
        this.mgfSpec = mgfSpec;
        this.pSrc = pSrc;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public String getDigestAlgorithm() {
        return mdName;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public String getMGFAlgorithm() {
        return mgfName;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public AlgorithmParameterSpec getMGFParameters() {
        return mgfSpec;
    }

    /**
     * @com.intel.drl.spec_ref
     */
    public PSource getPSource() {
        return pSrc;
    }
}

