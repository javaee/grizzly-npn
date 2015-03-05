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
import java.util.LinkedHashSet;

/**
 * enum {
 *    next_protocol_negotiation(13172), (65535)
 * } ExtensionType;
 *
 * The "extension_data" field of a "next_protocol_negotiation" extension
 * in a "ClientHello" MUST be empty.
 *
 * The "extension_data" field of a "next_protocol_negotiation" extension
 * in a "ServerHello" contains an optional list of protocols advertised
 * by the server.  Protocols are named by opaque, non-empty byte strings
 * and the list of protocols is serialized as a concatenation of 8-bit,
 * length prefixed byte strings.  Implementations MUST ensure that the
 * empty string is not included and that no byte strings are truncated.
 */
final class NextProtocolNegotiationExtension extends HelloExtension {

    private static final LinkedHashSet<String> EMPTY = new LinkedHashSet<>(0);

    // registry value TBD - NPN Draft 03 defines 13172 (0x3374).
    public static final int EXTENSION_ID = 0x3374;

    LinkedHashSet<String> protocols;
    private byte[] outData;

    // ------------------------------------------------------------ Constructors

    public NextProtocolNegotiationExtension(final ExtensionType extensionType) {
        super(extensionType);
        protocols = EMPTY;
    }

    // --------------------------------------------- Methods from HelloExtension


    @Override
    int length() {
        // Length of the encoded extension, including the type and length fields
        // - Two bytes for the type
        // - Two bytes for the length of the encoded protocols
        // - length of the encoded protocols
        return 4 + outData.length;
    }

    @Override
    void send(HandshakeOutStream handshakeOutStream) throws IOException {
        handshakeOutStream.putInt16(EXTENSION_ID);
        handshakeOutStream.putInt16(outData.length);
        handshakeOutStream.write(outData);
    }

    @Override
    public String toString() {
        return String.format(
                "Next Protocol Negotiation Extension [0x%x/%d], protocols: %s, compressed data: %s",
                EXTENSION_ID,
                EXTENSION_ID,
                protocols.toString(),
                Debug.toString(outData));
    }


    // ------------------------------------------------- Package Private Methods

    static Builder builder() {
        return new Builder();
    }

    // --------------------------------------------------------- Private Methods


    // ---------------------------------------------------------- Nested Classes


    static final class Builder {

        private static final byte[] EMPTY_DATA = new byte[0];
        public static final String ISO_8859_1 = "ISO-8859-1";

        private final NextProtocolNegotiationExtension extension =
                new NextProtocolNegotiationExtension(ExtensionType.get(EXTENSION_ID));

        private HandshakeInStream in;
        private int len;

        Builder protocols(final LinkedHashSet<String> protocols) {
            extension.protocols = protocols;
            return this;
        }

        Builder handshakeIn(final HandshakeInStream in, final int len) {
            this.in = in;
            this.len = len;
            return this;
        }

        NextProtocolNegotiationExtension build() throws IOException {
            if (in != null) {
                if (len > 0) {
                    extension.protocols = new LinkedHashSet<>();
                    int read = 0;
                    while (read != len) {
                        // Draft-03, section 3 states:
                        //    "Protocols are named by opaque, non-empty byte strings
                        //     and the list of protocols is serialized as a concatenation
                        //     of 8-bit length prefixed byte strings."
                        byte[] protocol = new byte[in.getInt8()];
                        in.read(protocol);
                        // the character encoding isn't specified by Draft-03.
                        // Given the examples in the draft, and our current usage,
                        // ISO-8859-1 seems sufficient.
                        extension.protocols.add(new String(protocol, ISO_8859_1));
                        read += protocol.length + 1; // add one for the length prefix
                    }
                } else {
                    extension.protocols = EMPTY;
                }
            } else {
                if (extension.protocols.isEmpty()) {
                    extension.outData = EMPTY_DATA;
                } else {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    for (String protocol : extension.protocols) {
                        out.write(protocol.length());
                        out.write(protocol.getBytes(ISO_8859_1));
                    }
                    extension.outData = out.toByteArray();
                }
            }
            return extension;
        }

    } // END Builder

} // END NextProtocolNegotiationExtension
