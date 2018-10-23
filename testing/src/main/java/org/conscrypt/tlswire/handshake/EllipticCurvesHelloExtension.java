/*
 * Copyright (C) 2016 The Android Open Source Project
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
package org.conscrypt.tlswire.handshake;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.conscrypt.tlswire.util.IoUtils;

/**
 * {@code elliptic_curves} {@link HelloExtension} from RFC 4492 section 5.1.1.
 */
public class EllipticCurvesHelloExtension extends HelloExtension {
    public List<EllipticCurve> supported;
    public boolean wellFormed;
    @Override
    protected void parseData() throws IOException {
        byte[] ellipticCurvesListBytes = IoUtils.readTlsVariableLengthByteVector(
                new DataInputStream(new ByteArrayInputStream(data)), 0xffff);
        ByteArrayInputStream ellipticCurvesListIn =
                new ByteArrayInputStream(ellipticCurvesListBytes);
        DataInputStream in = new DataInputStream(ellipticCurvesListIn);
        wellFormed = (ellipticCurvesListIn.available() % 2) == 0;
        supported = new ArrayList<EllipticCurve>(ellipticCurvesListIn.available() / 2);
        while (ellipticCurvesListIn.available() >= 2) {
            int curve_id = in.readUnsignedShort();
            supported.add(EllipticCurve.fromIdentifier(curve_id));
        }
    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("HelloExtension{type: elliptic_curves, wellFormed: ");
        sb.append(wellFormed);
        sb.append(", supported: ");
        sb.append(supported);
        sb.append('}');
        return sb.toString();
    }
}
