/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2006-2017 Oracle and/or its affiliates. All rights reserved.
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

import java.io.IOException;
import java.io.PrintStream;
import java.util.*;
import javax.net.ssl.*;

/**
 * This file contains all the classes relevant to TLS Extensions for the
 * ClientHello and ServerHello messages. The extension mechanism and
 * several extensions are defined in RFC 3546. Additional extensions are
 * defined in the ECC RFC 4492.
 *
 * Currently, only the two ECC extensions are fully supported.
 *
 * The classes contained in this file are:
 *  . HelloExtensions: a List of extensions as used in the client hello
 *      and server hello messages.
 *  . ExtensionType: an enum style class for the extension type
 *  . HelloExtension: abstract base class for all extensions. All subclasses
 *      must be immutable.
 *
 *  . UnknownExtension: used to represent all parsed extensions that we do not
 *      explicitly support.
 *  . ServerNameExtension: the server_name extension.
 *  . SignatureAlgorithmsExtension: the signature_algorithms extension.
 *  . EllipticCurvesExtension: the ECC supported curves extension.
 *  . EllipticPointFormatsExtension: the ECC supported point formats
 *      (compressed/uncompressed) extension.
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 */
final class HelloExtensions {

    private List<HelloExtension> extensions;
    private int encodedLength;

    HelloExtensions() {
        extensions = Collections.emptyList();
    }

    HelloExtensions(HandshakeInStream s) throws IOException {
        int len = s.getInt16();
        extensions = new ArrayList<HelloExtension>();
        encodedLength = len + 2;
        while (len > 0) {
            int type = s.getInt16();
            int extlen = s.getInt16();
            ExtensionType extType = ExtensionType.get(type);
            HelloExtension extension;
            if (extType == ExtensionType.EXT_SERVER_NAME) {
                extension = new ServerNameExtension(s, extlen);
            } else if (extType == ExtensionType.EXT_SIGNATURE_ALGORITHMS) {
                extension = new SignatureAlgorithmsExtension(s, extlen);
            } else if (extType == ExtensionType.EXT_ELLIPTIC_CURVES) {
                extension = new EllipticCurvesExtension(s, extlen);
            } else if (extType == ExtensionType.EXT_EC_POINT_FORMATS) {
                extension = new EllipticPointFormatsExtension(s, extlen);
            } else if (extType == ExtensionType.EXT_RENEGOTIATION_INFO) {
                extension = new RenegotiationInfoExtension(s, extlen);
            // BEGIN GRIZZLY NPN
            } else if (extType == ExtensionType.EXT_NEXT_PROTOCOL_NEGOTIATION) {
                extension = NextProtocolNegotiationExtension.builder().handshakeIn(s, extlen).build();
            } else if (extType == ExtensionType.EXT_APPLICATION_LEVEL_PROTOCOL_NEGOTIATION) {
                extension = AlpnExtension.builder().handshakeIn(s, extlen).build();
            // END GRIZZLY NPN
            } else if (extType == ExtensionType.EXT_EXTENDED_MASTER_SECRET) {
                extension = new ExtendedMasterSecretExtension(s, extlen);
            } else {
                extension = new UnknownExtension(s, extlen, extType);
            }
            extensions.add(extension);
            len -= extlen + 4;
        }
        if (len != 0) {
            throw new SSLProtocolException(
                        "Error parsing extensions: extra data");
        }
    }

    // Return the List of extensions. Must not be modified by the caller.
    List<HelloExtension> list() {
        return extensions;
    }

    void add(HelloExtension ext) {
        if (extensions.isEmpty()) {
            extensions = new ArrayList<HelloExtension>();
        }
        extensions.add(ext);
        encodedLength = -1;
    }

    HelloExtension get(ExtensionType type) {
        for (HelloExtension ext : extensions) {
            if (ext.type == type) {
                return ext;
            }
        }
        return null;
    }

    int length() {
        if (encodedLength >= 0) {
            return encodedLength;
        }
        if (extensions.isEmpty()) {
            encodedLength = 0;
        } else {
            encodedLength = 2;
            for (HelloExtension ext : extensions) {
                encodedLength += ext.length();
            }
        }
        return encodedLength;
    }

    void send(HandshakeOutStream s) throws IOException {
        int length = length();
        if (length == 0) {
            return;
        }
        s.putInt16(length - 2);
        for (HelloExtension ext : extensions) {
            ext.send(s);
        }
    }

    void print(PrintStream s) throws IOException {
        for (HelloExtension ext : extensions) {
            s.println(ext.toString());
        }
    }
}
