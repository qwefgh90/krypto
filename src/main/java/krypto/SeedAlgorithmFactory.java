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

import krypto.exception.WrongInitialVectorException;
import krypto.algorithm.seed.CBCMode;
import krypto.algorithm.seed.ECBMode;

import java.security.InvalidKeyException;

/**
 * This class includes a bunch of static factory methods for SEED
 */
public class SeedAlgorithmFactory {
    public static Algorithm createWithECB(String masterKey) throws InvalidKeyException {
        checkMasterKey(masterKey);
        return new ECBMode(masterKey);
    }

    /**
     *
     * @param masterKey
     * @param initialVector Initialization vector (IV) parameter with a length of 16 bytes.
     * @return
     */
    public static Algorithm createWithCBC(String masterKey, byte[] initialVector) throws WrongInitialVectorException, InvalidKeyException {
        checkIV(initialVector);
        checkMasterKey(masterKey);
        return new CBCMode(masterKey, initialVector);
    }

    private static void checkMasterKey(String masterKey) throws InvalidKeyException {
        if(masterKey == null || masterKey.isEmpty())
            throw new InvalidKeyException("masterKey can't not be empty.");
    }

    private static void checkIV(byte[] initialVector) throws WrongInitialVectorException {
        if(initialVector.length != 16)
            throw new WrongInitialVectorException("A length of initialVector must be 16 bytes.");
    }
}
