/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2003-2017 Oracle and/or its affiliates. All rights reserved.
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

import javax.net.ssl.*;

/*
 * A simple class to congregate alerts, their definitions, and common
 * support methods.
 */

final class Alerts {

    /*
     * Alerts are always a fixed two byte format (level/description).
     */

    // warnings and fatal errors are package private facilities/constants

    // Alert levels (enum AlertLevel)
    static final byte           alert_warning = 1;
    static final byte           alert_fatal = 2;

    /*
     * Alert descriptions (enum AlertDescription)
     *
     * We may not use them all in our processing, but if someone
     * sends us one, we can at least convert it to a string for the
     * user.
     */
    static final byte           alert_close_notify = 0;
    static final byte           alert_unexpected_message = 10;
    static final byte           alert_bad_record_mac = 20;
    static final byte           alert_decryption_failed = 21;
    static final byte           alert_record_overflow = 22;
    static final byte           alert_decompression_failure = 30;
    static final byte           alert_handshake_failure = 40;
    static final byte           alert_no_certificate = 41;
    static final byte           alert_bad_certificate = 42;
    static final byte           alert_unsupported_certificate = 43;
    static final byte           alert_certificate_revoked = 44;
    static final byte           alert_certificate_expired = 45;
    static final byte           alert_certificate_unknown = 46;
    static final byte           alert_illegal_parameter = 47;
    static final byte           alert_unknown_ca = 48;
    static final byte           alert_access_denied = 49;
    static final byte           alert_decode_error = 50;
    static final byte           alert_decrypt_error = 51;
    static final byte           alert_export_restriction = 60;
    static final byte           alert_protocol_version = 70;
    static final byte           alert_insufficient_security = 71;
    static final byte           alert_internal_error = 80;
    static final byte           alert_user_canceled = 90;
    static final byte           alert_no_renegotiation = 100;

    // from RFC 3546 (TLS Extensions)
    static final byte           alert_unsupported_extension = 110;
    static final byte           alert_certificate_unobtainable = 111;
    static final byte           alert_unrecognized_name = 112;
    static final byte           alert_bad_certificate_status_response = 113;
    static final byte           alert_bad_certificate_hash_value = 114;

    // BEGIN GRIZZLY NPN
    // ALPN alerts
    static final byte           alert_no_application_protocol = 120;
    // END GRIZZLY NPN

    static String alertDescription(byte code) {
        switch (code) {

        case alert_close_notify:
            return "close_notify";
        case alert_unexpected_message:
            return "unexpected_message";
        case alert_bad_record_mac:
            return "bad_record_mac";
        case alert_decryption_failed:
            return "decryption_failed";
        case alert_record_overflow:
            return "record_overflow";
        case alert_decompression_failure:
            return "decompression_failure";
        case alert_handshake_failure:
            return "handshake_failure";
        case alert_no_certificate:
            return "no_certificate";
        case alert_bad_certificate:
            return "bad_certificate";
        case alert_unsupported_certificate:
            return "unsupported_certificate";
        case alert_certificate_revoked:
            return "certificate_revoked";
        case alert_certificate_expired:
            return "certificate_expired";
        case alert_certificate_unknown:
            return "certificate_unknown";
        case alert_illegal_parameter:
            return "illegal_parameter";
        case alert_unknown_ca:
            return "unknown_ca";
        case alert_access_denied:
            return "access_denied";
        case alert_decode_error:
            return "decode_error";
        case alert_decrypt_error:
            return "decrypt_error";
        case alert_export_restriction:
            return "export_restriction";
        case alert_protocol_version:
            return "protocol_version";
        case alert_insufficient_security:
            return "insufficient_security";
        case alert_internal_error:
            return "internal_error";
        case alert_user_canceled:
            return "user_canceled";
        case alert_no_renegotiation:
            return "no_renegotiation";
        case alert_unsupported_extension:
            return "unsupported_extension";
        case alert_certificate_unobtainable:
            return "certificate_unobtainable";
        case alert_unrecognized_name:
            return "unrecognized_name";
        case alert_bad_certificate_status_response:
            return "bad_certificate_status_response";
        case alert_bad_certificate_hash_value:
            return "bad_certificate_hash_value";
        // BEGIN GRIZZLY NPN
        case alert_no_application_protocol:
            return "no_application_protocol";
        // END GRIZZLY NPN

        default:
            return "<UNKNOWN ALERT: " + (code & 0x0ff) + ">";
        }
    }

    static SSLException getSSLException(byte description, String reason) {
        return getSSLException(description, null, reason);
    }

    /*
     * Try to be a little more specific in our choice of
     * exceptions to throw.
     */
    static SSLException getSSLException(byte description, Throwable cause,
            String reason) {

        SSLException e;
        // the SSLException classes do not have a no-args constructor
        // make up a message if there is none
        if (reason == null) {
            if (cause != null) {
                reason = cause.toString();
            } else {
                reason = "";
            }
        }
        switch (description) {
        case alert_handshake_failure:
        case alert_no_certificate:
        case alert_bad_certificate:
        case alert_unsupported_certificate:
        case alert_certificate_revoked:
        case alert_certificate_expired:
        case alert_certificate_unknown:
        case alert_unknown_ca:
        case alert_access_denied:
        case alert_decrypt_error:
        case alert_export_restriction:
        case alert_insufficient_security:
        case alert_unsupported_extension:
        case alert_certificate_unobtainable:
        case alert_unrecognized_name:
        case alert_bad_certificate_status_response:
        case alert_bad_certificate_hash_value:
            e = new SSLHandshakeException(reason);
            break;

        case alert_close_notify:
        case alert_unexpected_message:
        case alert_bad_record_mac:
        case alert_decryption_failed:
        case alert_record_overflow:
        case alert_decompression_failure:
        case alert_illegal_parameter:
        case alert_decode_error:
        case alert_protocol_version:
        case alert_internal_error:
        case alert_user_canceled:
        case alert_no_renegotiation:
        default:
            e = new SSLException(reason);
            break;
        }

        if (cause != null) {
            e.initCause(cause);
        }
        return e;
    }
}
