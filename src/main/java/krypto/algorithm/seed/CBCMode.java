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

package krypto.algorithm.seed;

import krypto.algorithm.seed.impl.cbc.KISA_SEED_CBC;

public class CBCMode extends SeedAlgorithm{
    byte[] iv;
    public CBCMode(String masterKey, byte[] initialVector) {
        super(masterKey, Mode.CBC);
        assert initialVector.length == 16;
        this.iv = initialVector;
    }

    @Override
    public byte[] encrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Encrypt(keyBytes, iv, bytes, 0, bytes.length);
    }

    @Override
    public byte[] decrypt(byte[] bytes) {
        return KISA_SEED_CBC.SEED_CBC_Decrypt(keyBytes, iv, bytes, 0, bytes.length);
    }
}
