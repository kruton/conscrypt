/*
 * Copyright (C) 2007 The Android Open Source Project
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

/**
 * An implementation of {@link SSLSocketFactory} based on BoringSSL.
 *
 * <p/>This name of this class cannot change in order to maintain backward-compatibility with GMS
 * core {@code ProviderInstallerImpl}
 */
final class OpenSSLSocketFactoryImpl extends SSLSocketFactory {
    private static boolean useEngineSocketByDefault = SSLUtils.USE_ENGINE_SOCKET_BY_DEFAULT;

    private final SSLParametersImpl sslParameters;
    private final IOException instantiationException;
    private boolean useEngineSocket = useEngineSocketByDefault;
    private final HashMap<Long, TLSCustomExtensionCallbacks> tlsCustomExtensions = new HashMap<>();

    OpenSSLSocketFactoryImpl() {
        SSLParametersImpl sslParametersLocal = null;
        IOException instantiationExceptionLocal = null;
        try {
            sslParametersLocal = SSLParametersImpl.getDefault();
        } catch (KeyManagementException e) {
            instantiationExceptionLocal = new IOException("Delayed instantiation exception:", e);
        }
        this.sslParameters = sslParametersLocal;
        this.instantiationException = instantiationExceptionLocal;
    }

    OpenSSLSocketFactoryImpl(SSLParametersImpl sslParameters) {
        this.sslParameters = sslParameters;
        this.instantiationException = null;
    }

    /**
     * Configures the default socket to be created for all instances.
     */
    static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        useEngineSocketByDefault = useEngineSocket;
    }

    /**
     * Configures the socket to be created for this instance. If not called,
     * {@link #useEngineSocketByDefault} will be used.
     */
    void setUseEngineSocket(boolean useEngineSocket) {
        this.useEngineSocket = useEngineSocket;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslParameters.getEnabledCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        if (instantiationException != null) {
            throw instantiationException;
        }
        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (useEngineSocket) {
            return new ConscryptEngineSocket(sslParametersLocal);
        } else {
            return new ConscryptFileDescriptorSocket(sslParametersLocal);
        }
    }

    @Override
    public Socket createSocket(String hostname, int port) throws IOException, UnknownHostException {
        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (useEngineSocket) {
            return new ConscryptEngineSocket(hostname, port, sslParametersLocal);
        } else {
            return new ConscryptFileDescriptorSocket(hostname, port, sslParametersLocal);
        }
    }

    @Override
    public Socket createSocket(String hostname, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (useEngineSocket) {
            return new ConscryptEngineSocket(
                    hostname, port, localHost, localPort, sslParametersLocal);
        } else {
            return new ConscryptFileDescriptorSocket(
                    hostname, port, localHost, localPort, sslParametersLocal);
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (useEngineSocket) {
            return new ConscryptEngineSocket(address, port, sslParametersLocal);
        } else {
            return new ConscryptFileDescriptorSocket(address, port, sslParametersLocal);
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
            int localPort) throws IOException {
        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (useEngineSocket) {
            return new ConscryptEngineSocket(
                    address, port, localAddress, localPort, sslParametersLocal);
        } else {
            return new ConscryptFileDescriptorSocket(
                    address, port, localAddress, localPort, sslParametersLocal);
        }
    }

    @Override
    public Socket createSocket(Socket socket, String hostname, int port, boolean autoClose)
            throws IOException {
        Preconditions.checkNotNull(socket, "socket");
        if (!socket.isConnected()) {
            throw new SocketException("Socket is not connected.");
        }

        SSLParametersImpl sslParametersLocal = (SSLParametersImpl) sslParameters.clone();
        if (hasFileDescriptor(socket) && !useEngineSocket) {
            return new ConscryptFileDescriptorSocket(
                    socket, hostname, port, autoClose, sslParametersLocal);
        } else {
            return new ConscryptEngineSocket(socket, hostname, port, autoClose, sslParametersLocal);
        }
    }

    private boolean hasFileDescriptor(Socket s) {
        try {
            // If socket has a file descriptor we can use it directly
            // otherwise we need to use the engine.
            Platform.getFileDescriptor(s);
            return true;
        } catch (RuntimeException re) {
            return false;
        }
    }
}
