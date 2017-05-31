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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/**
 * This interface should be implemented by those wishing to add a custom TLS extension to a {@code
 * ClientHello} or {@code ServerHello} during a TLS handshake via either {@link
 * javax.net.ssl.SSLSocket} or {@link javax.net.ssl.SSLEngine}. The return {@link
 * TLSCustomExtensionData} can either send a TLS alert or add a TLS extension.
 */
public interface TLSCustomExtensionCallbacks {
    TLSCustomExtensionData addClientCustomExtension(SSLSocket socket);
    TLSCustomExtensionData addClientCustomExtension(SSLEngine engine);

    TLSCustomExtensionData addServerCustomExtension(SSLSocket socket);
    TLSCustomExtensionData addServerCustomExtension(SSLEngine engine);

    void parseCustomExtension(SSLSocket socket, byte[] data);
    void parseCustomExtension(SSLEngine socket, byte[] data);
}
