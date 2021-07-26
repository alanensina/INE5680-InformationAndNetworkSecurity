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
    private Key aesKey;
    private byte iv[];
    private IvParameterSpec ivSpec;
    private Cipher cipher;

    public static AESwithCTR getInstance() {
        if (instance == null) {
            instance = new AESwithCTR();
        }
        return instance;
    }

    public String encrypt(String strToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        // TODO - Externalizar trecho de código - INICIO
        // Instancia o cipher
        cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");

        // Gera uma chave AES
        System.out.print("Gerando chave \t-> ");
        KeyGenerator sKenGen;
        sKenGen = KeyGenerator.getInstance("AES", "BCFIPS");
        aesKey = sKenGen.generateKey();
        System.out.println("Chave AES \t= " + Hex.encodeHexString(aesKey.getEncoded()));

        // Gerando o iv com SecureRandom
        System.out.print("Gerando IV \t-> ");
        SecureRandom random = SecureRandom.getInstance("DEFAULT", "BCFIPS");
        iv = new byte[16];
        random.nextBytes(iv);
        ivSpec = new IvParameterSpec(iv);
        System.out.println("IV \t= " + Hex.encodeHexString(iv));
        // TODO - Externalizar trecho de código - FIM

        try {
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            final String encryptedString = Hex.encodeHexString(cipher.doFinal(strToEncrypt.getBytes()));
            return encryptedString;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
        }
        return null;

    }

    public String decrypt(String strEncrypted) throws InvalidAlgorithmParameterException, InvalidKeyException {
        try {

            cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            byte[] embytes = {};
            try {
                embytes = Hex.decodeHex(strEncrypted.toCharArray());
            } catch (DecoderException ex) {
                Logger.getLogger(AESwithCTR.class.getName()).log(Level.SEVERE, null, ex);
            }

            String decryptedString = new String(cipher.doFinal(embytes));

            return decryptedString;

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println(e);
        }
        return null;
    }
}
