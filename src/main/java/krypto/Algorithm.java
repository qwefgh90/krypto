package krypto;

public abstract class Algorithm {

    protected final Kind kind;

    protected final String masterKey;
    protected final byte[] keyBytes;
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
     * @param bytes any plain text
     * @return
     */
    public abstract byte[] encrypt(byte[] bytes);

    /**
     * @param bytes any cipher text which is encrypted with supported algorithms
     * @return
     */
    public abstract byte[] decrypt(byte[] bytes);

    public enum Kind {
        ARIA,
        SEED,
        LEA
    }
}
