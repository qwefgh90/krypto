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

package krypto.algorithm.lea;

import krypto.Algorithm;
import krypto.util.EncryptionUtils;

/**
 * Key size: 128, 192, 256 bits
 * Block size: 128 bites
 */
public abstract class LeaAlgorithm extends Algorithm {
    protected final Mode mode;
    public LeaAlgorithm(String masterKey, int fixedKeySize, Mode mode) {
        super(Kind.LEA, masterKey, EncryptionUtils.getMasterKeyWithFixedLength(masterKey, fixedKeySize), fixedKeySize);
        assert fixedKeySize == 256 || fixedKeySize == 192 || fixedKeySize == 128;
        this.mode = mode;
    }

    public Mode getMode() {
        return mode;
    }

    public abstract byte[] encrypt(byte[] bytes);

    public abstract byte[] decrypt(byte[] bytes);

    public enum Mode {
        ECB,
        CBC
    }
}
