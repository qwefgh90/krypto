package kisa;

import java.security.InvalidKeyException;

public abstract class AlgorithmFactory {
    public abstract Algorithm create() throws InvalidKeyException;
}
