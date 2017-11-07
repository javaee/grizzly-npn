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

import java.util.ArrayList;
import java.util.List;

final class ExtensionType {

    final int id;
    final String name;

    private ExtensionType(int id, String name) {
        this.id = id;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    static List<ExtensionType> knownExtensions = new ArrayList<ExtensionType>(9);

    static ExtensionType get(int id) {
        for (ExtensionType ext : knownExtensions) {
            if (ext.id == id) {
                return ext;
            }
        }
        return new ExtensionType(id, "type_" + id);
    }

    private static ExtensionType e(int id, String name) {
        ExtensionType ext = new ExtensionType(id, name);
        knownExtensions.add(ext);
        return ext;
    }

    // extensions defined in RFC 3546
    final static ExtensionType EXT_SERVER_NAME =
            e(0x0000, "server_name");            // IANA registry value: 0
    final static ExtensionType EXT_MAX_FRAGMENT_LENGTH =
            e(0x0001, "max_fragment_length");    // IANA registry value: 1
    final static ExtensionType EXT_CLIENT_CERTIFICATE_URL =
            e(0x0002, "client_certificate_url"); // IANA registry value: 2
    final static ExtensionType EXT_TRUSTED_CA_KEYS =
            e(0x0003, "trusted_ca_keys");        // IANA registry value: 3
    final static ExtensionType EXT_TRUNCATED_HMAC =
            e(0x0004, "truncated_hmac");         // IANA registry value: 4
    final static ExtensionType EXT_STATUS_REQUEST =
            e(0x0005, "status_request");         // IANA registry value: 5

    // extensions defined in RFC 4681
    final static ExtensionType EXT_USER_MAPPING =
            e(0x0006, "user_mapping");           // IANA registry value: 6

    // extensions defined in RFC 5081
    final static ExtensionType EXT_CERT_TYPE =
            e(0x0009, "cert_type");              // IANA registry value: 9

    // extensions defined in RFC 4492 (ECC)
    final static ExtensionType EXT_ELLIPTIC_CURVES =
            e(0x000A, "elliptic_curves");        // IANA registry value: 10
    final static ExtensionType EXT_EC_POINT_FORMATS =
            e(0x000B, "ec_point_formats");       // IANA registry value: 11

    // extensions defined in RFC 5054
    final static ExtensionType EXT_SRP =
            e(0x000C, "srp");                    // IANA registry value: 12

    // extensions defined in RFC 5246
    final static ExtensionType EXT_SIGNATURE_ALGORITHMS =
            e(0x000D, "signature_algorithms");   // IANA registry value: 13

    // extensions defined in RFC 5746
    final static ExtensionType EXT_RENEGOTIATION_INFO =
            e(0xff01, "renegotiation_info");     // IANA registry value: 65281
    // START GRIZZLY NPN
    // extension defined in draft-ietf-tls-applayerprotoneg
    final static ExtensionType EXT_APPLICATION_LEVEL_PROTOCOL_NEGOTIATION =
            e(AlpnExtension.ID, AlpnExtension.NAME); // IANA registry value: 16


    // extension defined in http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03
    // This value may change.  Draft 04 currently doesn't define a value here.
    final static ExtensionType EXT_NEXT_PROTOCOL_NEGOTIATION =
            e(NextProtocolNegotiationExtension.EXTENSION_ID,
              "next_protocol_negotiation");
    // END GRIZZLY NPN
}
