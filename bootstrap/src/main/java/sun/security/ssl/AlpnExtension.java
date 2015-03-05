/*
 * Copyright (c) 2012, 2015 Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package sun.security.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class AlpnExtension extends HelloExtension {

    private static final String ALPN_TO_STRING_MSG =
            "Application Layer Protocol Extension (ALPN) [0x%x/%d], " +
                    "client protocols: %s, selected protocol: %s, serialized " +
                    "data: %s";

    static final int ID = 0x0010;
    static final String NAME = "alpn";

    String selectedProtocol;
    String[] protocols;
    byte[] outData;

    AlpnExtension(ExtensionType extensionType) {
        super(extensionType);
    }

    @Override
    int length() {
        // Length of the encoded extension, including the type and length fields
        // - Two bytes for the extension type
        // - Two bytes for the extension length
        // - Two bytes for the name list length
        // - length of the encoded protocols
        return 6 + (short) outData.length;
    }

    @Override
    void send(HandshakeOutStream handshakeOutStream) throws IOException {
        handshakeOutStream.putInt16(ID);
        handshakeOutStream.putInt16(outData.length + 2);
        handshakeOutStream.putInt16(outData.length);
        handshakeOutStream.write(outData);
    }

    @Override
    public String toString() {
        return String.format(ALPN_TO_STRING_MSG,
                             ID,
                             ID,
                             Arrays.toString(protocols),
                             selectedProtocol,
                             Debug.toString(outData));
    }

    static Builder builder() {
        return new Builder();
    }


    static final class Builder {

        private static final byte[] EMPTY_DATA = new byte[0];
        private static final String[] NO_PROTOCOLS = new String[0];


        private final AlpnExtension extension =
                new AlpnExtension(ExtensionType.get(ID));

        private HandshakeInStream in;
        private int len;

        Builder selectedProtocol(final String selectedProtocol) {
            extension.selectedProtocol = selectedProtocol;
            return this;
        }

        Builder protocols(final String[] protocols) {
            extension.protocols = protocols;
            return this;
        }

        Builder handshakeIn(final HandshakeInStream in, final int len) {
            this.in = in;
            // TODO len shouldn't be more than 2^16-1
            this.len = len;
            return this;
        }

        AlpnExtension build() throws IOException {
            if (in != null) {
                if (len > 0) {
                    final List<String> list = new ArrayList<>(4);
                    int read = 0;
                    int newLen = in.getInt16();
                    while (read != newLen) {
                        // Draft-03, section 3 states:
                        //    "Protocols are named by opaque, non-empty byte strings
                        //     and the list of protocols is serialized as a concatenation
                        //     of 8-bit length prefixed byte strings."
                        byte[] protocol = new byte[in.getInt8()];
                        in.read(protocol);
                        // the character encoding currently specified is UTF-8.
                        // TODO, make this lazy.
                        list.add(new String(protocol, "UTF-8"));
                        read += protocol.length + 1; // add one for the length prefix
                    }
                    extension.protocols = list.toArray(new String[list.size()]);
                } else {
                    extension.protocols = NO_PROTOCOLS;
                }
            } else {
                if (extension.selectedProtocol != null) {
                    final byte[] selectedProtocolBytes =
                            extension.selectedProtocol.getBytes("UTF-8");
                    
                    final byte[] outBytes = new byte[selectedProtocolBytes.length + 1];
                    outBytes[0] = (byte) selectedProtocolBytes.length;
                    System.arraycopy(selectedProtocolBytes, 0,
                            outBytes, 1, selectedProtocolBytes.length);
                    
                    extension.outData = outBytes;
                } else {
                    if (extension.protocols.length == 0) {
                        extension.outData = EMPTY_DATA;
                    } else {
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        for (String protocol : extension.protocols) {
                            if (protocol.length() > 0 && protocol.length() < 256) {
                                out.write((byte) protocol.length());
                                out.write(protocol.getBytes("UTF-8"));
                            } else {
                                // TODO add logging for the case where the
                                // protocol is an empty string or greater than 2^8-1.
                            }
                        }
                        // TODO len of outData shouldn't be more than 2^16-1
                        extension.outData = out.toByteArray();
                    }
                }
            }
            return extension;
        }

    } // END Builder

} // END AlpnExtension