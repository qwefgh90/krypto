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
