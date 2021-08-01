package model;

public class LittlePackage {
    private int ctLength;
    private byte[] cipherText;
    private String encryptedMessage;

    public LittlePackage(int ctLength, byte[] cipherText, String encryptedMessage) {
        this.ctLength = ctLength;
        this.cipherText = cipherText;
        this.encryptedMessage = encryptedMessage;
    }

    public int getCtLength() {
        return ctLength;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public String getEncryptedMessage() {
        return encryptedMessage;
    }
}
