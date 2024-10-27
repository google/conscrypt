/*
 * Copyright (C) 2014 The Android Open Source Project
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

import java.io.DataInput;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.conscrypt.tlswire.util.IoUtils;

/**
 * {@code HelloExtension} struct from TLS 1.2 RFC 5246.
 */
public class HelloExtension {
    public static final int TYPE_SERVER_NAME = 0;
    public static final int TYPE_ELLIPTIC_CURVES = 10;
    public static final int TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
    public static final int TYPE_PADDING = 21;
    public static final int TYPE_SESSION_TICKET = 35;
    public static final int TYPE_RENEGOTIATION_INFO = 65281;
    private static final Map<Integer, String> TYPE_TO_NAME = new HashMap<>();
    static {
        TYPE_TO_NAME.put(TYPE_SERVER_NAME, "server_name");
        TYPE_TO_NAME.put(1, "max_fragment_length");
        TYPE_TO_NAME.put(2, "client_certificate_url");
        TYPE_TO_NAME.put(3, "trusted_ca_keys");
        TYPE_TO_NAME.put(4, "truncated_hmac");
        TYPE_TO_NAME.put(5, "status_request");
        TYPE_TO_NAME.put(6, "user_mapping");
        TYPE_TO_NAME.put(7, "client_authz");
        TYPE_TO_NAME.put(8, "server_authz");
        TYPE_TO_NAME.put(9, "cert_type");
        TYPE_TO_NAME.put(TYPE_ELLIPTIC_CURVES, "elliptic_curves");
        TYPE_TO_NAME.put(11, "ec_point_formats");
        TYPE_TO_NAME.put(12, "srp");
        TYPE_TO_NAME.put(13, "signature_algorithms");
        TYPE_TO_NAME.put(14, "use_srtp");
        TYPE_TO_NAME.put(15, "heartbeat");
        TYPE_TO_NAME.put(TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, "application_layer_protocol_negotiation");
        TYPE_TO_NAME.put(17, "status_request_v2");
        TYPE_TO_NAME.put(18, "signed_certificate_timestamp");
        TYPE_TO_NAME.put(19, "client_certificate_type");
        TYPE_TO_NAME.put(20, "server_certificate_type");
        TYPE_TO_NAME.put(TYPE_PADDING, "padding");
        TYPE_TO_NAME.put(TYPE_SESSION_TICKET, "SessionTicket");
        TYPE_TO_NAME.put(13172, "next_protocol_negotiation");
        TYPE_TO_NAME.put(30031, "Channel ID (old)");
        TYPE_TO_NAME.put(30032, "Channel ID (new)");
        TYPE_TO_NAME.put(TYPE_RENEGOTIATION_INFO, "renegotiation_info");
    }
    public int type;
    public String name;
    public byte[] data;
    public static HelloExtension read(DataInput in) throws IOException {
        int type = in.readUnsignedShort();
        HelloExtension result;
        switch (type) {
            case TYPE_SERVER_NAME:
                result = new ServerNameHelloExtension();
                break;
            case TYPE_ELLIPTIC_CURVES:
                result = new EllipticCurvesHelloExtension();
                break;
            case TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                result = new AlpnHelloExtension();
                break;
            default:
                result = new HelloExtension();
                break;
        }
        result.type = type;
        result.name = TYPE_TO_NAME.get(result.type);
        if (result.name == null) {
            result.name = String.valueOf(result.type);
        }
        result.data = IoUtils.readTlsVariableLengthByteVector(in, 0xffff);
        result.parseData();
        return result;
    }

    protected void parseData() throws IOException {}

    @Override
    public String toString() {
        return "HelloExtension{type: " + name + ", data: " + new BigInteger(1, data).toString(16)
                + "}";
    }
}
