package utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class AESwithCTR {
    private static AESwithCTR instance;
    private Cipher cipher;

    public static AESwithCTR getInstance() {
        if (instance == null) {
            instance = new AESwithCTR();
        }
        return instance;
    }

    public String encrypt(String strToEncrypt, Key aesKey, IvParameterSpec ivSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
            return Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error encrypting -> " + e.getMessage());
        }
    }

    public String decrypt(String strEncrypted, Key aesKey, IvParameterSpec ivSpec) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
            byte[] inBytes = Hex.decodeHex(strEncrypted.toCharArray());
            return new String(cipher.doFinal(inBytes));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | DecoderException e) {
            throw new RuntimeException("Error decrypting -> " + e.getMessage());
        }
    }
}
