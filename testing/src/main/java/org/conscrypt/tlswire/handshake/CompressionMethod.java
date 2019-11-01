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
/**
 * {@code CompressionMethod} enum from TLS 1.2 RFC 5246.
 */
public class CompressionMethod {
    public static final CompressionMethod NULL = new CompressionMethod(0, "null");
    public static final CompressionMethod DEFLATE = new CompressionMethod(1, "deflate");
    public final int type;
    public final String name;
    private CompressionMethod(int type, String name) {
        this.type = type;
        this.name = name;
    }
    public static CompressionMethod valueOf(int type) {
        switch (type) {
            case 0:
                return NULL;
            case 1:
                return DEFLATE;
            default:
                return new CompressionMethod(type, String.valueOf(type));
        }
    }
    @Override
    public String toString() {
        return name;
    }
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + type;
        return result;
    }
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof CompressionMethod)) {
            return false;
        }
        CompressionMethod other = (CompressionMethod) obj;
        if (type != other.type) {
            return false;
        }
        return true;
    }
}
