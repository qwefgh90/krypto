/*
 * Copyright 2023 qwefgh90
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package krypto;

public abstract class Algorithm {

    /**
     * The algorithm kind of this instance
     */
    protected final Kind kind;

    /**
     * The seed value for creating a secret key
     */
    protected final String masterKey;

    /**
     * A byte array of the masterKey
     */
    protected final byte[] keyBytes;

    /**
     * The length of the key for encryption and descryption
     */
    protected final int keyLength;

    public Algorithm(Kind kind, String masterKey, byte[] keyBytes, int keyLength) {
        this.kind = kind;
        this.masterKey = masterKey;
        this.keyBytes = keyBytes;
        this.keyLength = keyLength;
    }

    public Kind getKind() {
        return kind;
    }

    /**
     * Encrypt a plain text.
     * @param bytes Any plain text
     * @return A cipher text
     */
    public abstract byte[] encrypt(byte[] bytes);

    /**
     * Decrypt a cipher text.
     * @param bytes Any cipher text which is encrypted with supported algorithms
     * @return A decrypted text
     */
    public abstract byte[] decrypt(byte[] bytes);

    /**
     * This enum refers to a list of algorithms which implementation is provided.
     */
    public enum Kind {
        ARIA,
        SEED,
        LEA
    }
}
