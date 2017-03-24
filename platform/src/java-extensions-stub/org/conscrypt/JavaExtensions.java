/*
 * Copyright 2017 The Android Open Source Project
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

import java.io.FileDescriptor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.nio.channels.SocketChannel;
import java.security.spec.ECParameterSpec;

/**
 * Used for building on openjdk platforms. Copied from the Platform class for the OpenJDK.
 */
final class JavaExtensions {
    private static Method m_getCurveName;
    static {
        try {
            m_getCurveName = ECParameterSpec.class.getDeclaredMethod("getCurveName");
            m_getCurveName.setAccessible(true);
        } catch (Exception ignored) {
        }
    }

    private JavaExtensions() {}

    static FileDescriptor getFileDescriptor(Socket s) {
        try {
            SocketChannel channel = s.getChannel();
            if (channel != null) {
                Field f_fd = channel.getClass().getDeclaredField("fd");
                f_fd.setAccessible(true);
                return (FileDescriptor) f_fd.get(channel);
            }
        } catch (Exception e) {
            // Try socket class below...
        }

        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(s);
            Field f_fd = SocketImpl.class.getDeclaredField("fd");
            f_fd.setAccessible(true);
            return (FileDescriptor) f_fd.get(socketImpl);
        } catch (Exception e) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e);
        }
    }

    static FileDescriptor getFileDescriptorFromSSLSocket(OpenSSLSocketImpl openSSLSocketImpl) {
        return getFileDescriptor(openSSLSocketImpl);
    }

    static String getCurveName(ECParameterSpec spec) {
        if (m_getCurveName == null) {
            return null;
        }
        try {
            return (String) m_getCurveName.invoke(spec);
        } catch (Exception e) {
            return null;
        }
    }

    static void setCurveName(ECParameterSpec spec, String curveName) {
        // This doesn't appear to be needed.
    }

    /*
     * Call Os.setsockoptTimeval via reflection.
     */
    static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
        // TODO: figure this out on the RI
    }

    /**
     * Returns true if the supplied hostname is an literal IP address.
     */
    static boolean isLiteralIpAddress(String hostname) {
        // TODO: any RI API to make this better?
        return AddressUtils.isLiteralIpAddress(hostname);
    }

    /**
     * OID to Algorithm Name mapping.
     */
    static String oidToAlgorithmName(String oid) {
        // This doesn't appear to be needed.
        return "";
    }
}
