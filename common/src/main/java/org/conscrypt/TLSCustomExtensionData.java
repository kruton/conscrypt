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

import java.util.Arrays;

/**
 * This is returned by an implementation of a custom TLS extensions to add data to the handshake
 * response given via a {@code SSLSocket} or {@code SSLEngine} instances provided by Conscrypt.
 */
public final class TLSCustomExtensionData {
    private final Integer alertNumber;
    private final byte[] response;

    /**
     * When a custom TLS extension implementation wishes to send a TLS alert in a handshake, it
     * should set the {@code alertNumber} with this constructor.
     */
    public TLSCustomExtensionData(int alertNumber) {
        this.alertNumber = alertNumber;
        this.response = null;
    }

    /**
     * When a custom TLS extension implementation wishes to add data to the {@code ClientHello} or
     * {@code ServerHello} during a handshake, it should use this constructor to set {@code
     * response} to the TLS extension bytes to be added.
     */
    public TLSCustomExtensionData(byte[] response) {
        this.alertNumber = null;
        this.response = response;
    }

    @Override
    public String toString() {
        return "TLSCustomExtensionData{"
                + "alertNumber=" + alertNumber + ", response=" + Arrays.toString(response) + '}';
    }
}
