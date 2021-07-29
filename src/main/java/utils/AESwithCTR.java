package utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

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

            final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;

        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }
        return null;

    }

    public String decrypt(String strEncrypted, Key aesKey, IvParameterSpec ivSpec) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] inBytes = {};
            try {
                inBytes = Hex.decodeHex(strEncrypted.toCharArray());
            } catch (DecoderException ex) {
                Logger.getLogger(AESwithCTR.class.getName()).log(Level.SEVERE, null, ex);
            }

            String decryptedString = new String(cipher.doFinal(inBytes));
            return decryptedString;

        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println(e);
        }
        return null;
    }
}
