/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2013-2017 Oracle and/or its affiliates. All rights reserved.
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

package org.glassfish.grizzly.npn;

import javax.net.ssl.SSLEngine;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility class to register, obtain, and/or remove Client/Server NPN/ALPN
 * negotiator instances.
 */
public class NegotiationSupport {

    private static final ConcurrentHashMap<SSLEngine, ServerSideNegotiator> serverSideNegotiators =
            new ConcurrentHashMap<SSLEngine, ServerSideNegotiator>(4);
    private static final ConcurrentHashMap<SSLEngine, ClientSideNegotiator> clientSideNegotiators =
                new ConcurrentHashMap<SSLEngine, ClientSideNegotiator>(4);
    private static final ConcurrentHashMap<SSLEngine, AlpnServerNegotiator> alpnServerNegotiators =
                new ConcurrentHashMap<SSLEngine, AlpnServerNegotiator>(4);
        private static final ConcurrentHashMap<SSLEngine, AlpnClientNegotiator> alpnClientNegotiators =
                    new ConcurrentHashMap<SSLEngine, AlpnClientNegotiator>(4);

    /**
     * Add a {@link ServerSideNegotiator} that will be invoked when handshake
     * activity occurs against the specified {@link SSLEngine}.
     */
    public static void addNegotiator(final SSLEngine engine,
                                     final ServerSideNegotiator serverSideNegotiator) {
        serverSideNegotiators.putIfAbsent(engine, serverSideNegotiator);
    }

    /**
     * Add a {@link ClientSideNegotiator} that will be invoked when handshake
     * activity occurs against the specified {@link SSLEngine}.
     */
    public static void addNegotiator(final SSLEngine engine,
                                     final ClientSideNegotiator clientSideNegotiator) {
        clientSideNegotiators.putIfAbsent(engine, clientSideNegotiator);
    }

    /**
     * Add a {@link AlpnServerNegotiator} that will be invoked when handshake
     * activity occurs against the specified {@link SSLEngine}.
     */
    public static void addNegotiator(final SSLEngine engine,
                                     final AlpnServerNegotiator serverSideNegotiator) {
        alpnServerNegotiators.putIfAbsent(engine, serverSideNegotiator);
    }

    /**
     * Add a {@link AlpnClientNegotiator} that will be invoked when handshake
     * activity occurs against the specified {@link SSLEngine}.
     */
    public static void addNegotiator(final SSLEngine engine,
                                     final AlpnClientNegotiator clientSideNegotiator) {
        alpnClientNegotiators.putIfAbsent(engine, clientSideNegotiator);
    }

    /**
     * Disassociate the {@link ClientSideNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static ClientSideNegotiator removeClientNegotiator(final SSLEngine engine) {
        return clientSideNegotiators.remove(engine);
    }

    /**
     * Disassociate the {@link AlpnClientNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static AlpnClientNegotiator removeAlpnClientNegotiator(final SSLEngine engine) {
        return alpnClientNegotiators.remove(engine);
    }

    /**
     * Disassociate the {@link ServerSideNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static ServerSideNegotiator removeServerNegotiator(final SSLEngine engine) {
        return serverSideNegotiators.remove(engine);
    }

    /**
     * Disassociate the {@link AlpnServerNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static AlpnServerNegotiator removeAlpnServerNegotiator(final SSLEngine engine) {
        return alpnServerNegotiators.remove(engine);
    }

    /**
     * @return the {@link ServerSideNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static ServerSideNegotiator getServerSideNegotiator(final SSLEngine engine) {
        return serverSideNegotiators.get(engine);
    }

    /**
     * @return the {@link ClientSideNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static ClientSideNegotiator getClientSideNegotiator(final SSLEngine engine) {
        return clientSideNegotiators.get(engine);
    }

    /**
     * @return the {@link AlpnServerNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static AlpnServerNegotiator getAlpnServerNegotiator(final SSLEngine engine) {
        return alpnServerNegotiators.get(engine);
    }

    /**
     * @return the {@link AlpnClientNegotiator} associated with the specified
     * {@link SSLEngine}.
     */
    public static AlpnClientNegotiator getAlpnClientNegotiator(final SSLEngine engine) {
        return alpnClientNegotiators.get(engine);
    }

}
