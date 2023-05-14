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

import krypto.exception.WrongFixedKeySize;
import krypto.algorithm.lea.CBCMode;
import krypto.algorithm.lea.ECBMode;

import java.security.InvalidKeyException;

/**
 * This class includes a bunch of static factory methods for ARIA
 */
public class LeaAlgorithmFactory {
    /**
     *
     * @param masterKey
     * @param fixedKeySize 128, 192, 256 bits
     * @return
     * @throws InvalidKeyException
     * @throws WrongFixedKeySize
     */
    public static Algorithm createWithECB(String masterKey, int fixedKeySize) throws InvalidKeyException, WrongFixedKeySize {
        checkFixedKeySize(fixedKeySize);
        checkMasterKey(masterKey);
        return new ECBMode(masterKey, fixedKeySize);
    }

    /**
     *
     * @param masterKey
     * @param fixedKeySize
     * @param initialVector Initial vector with a length of 128 bits
     * @return
     * @throws InvalidKeyException
     * @throws WrongFixedKeySize
     */
    public static Algorithm createWithCBC(String masterKey, int fixedKeySize, byte[] initialVector) throws InvalidKeyException, WrongFixedKeySize {
        checkFixedKeySize(fixedKeySize);
        checkMasterKey(masterKey);
        return new CBCMode(masterKey, fixedKeySize, initialVector);
    }
    private static void checkMasterKey(String masterKey) throws InvalidKeyException {
        if(masterKey == null || masterKey.isEmpty())
            throw new InvalidKeyException("masterKey can't be empty.");
    }
    private static void checkFixedKeySize(int fixedKeySize) throws WrongFixedKeySize {
        if(!(fixedKeySize == 256 || fixedKeySize == 192 || fixedKeySize == 128))
            throw new WrongFixedKeySize("fixedKeySize is one of 256, 192 and 128.");
    }
}
