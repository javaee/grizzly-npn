/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012-2017 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://oss.oracle.com/licenses/CDDL+GPL-1.1
 * or LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
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
