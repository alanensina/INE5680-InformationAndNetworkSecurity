package service;


import org.apache.commons.codec.binary.Hex;
import utils.AESwithCTR;
import utils.PBKDF2UtilBCFIPS;
import utils.Utils;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptographyService {
    private Key aesKey;
    private IvParameterSpec ivSpec;

    public void initCrypto() throws NoSuchAlgorithmException, NoSuchProviderException {
        // TODO - Externalizar trecho de código - INICIO
        // Gera uma chave AES
        SecureRandom	random = new SecureRandom();
        System.out.print("Gerando chave \t-> ");
        aesKey = Utils.createKeyForAES(128, random);
        System.out.println("Chave AES \t= " + Hex.encodeHexString(aesKey.getEncoded()));

        // Gerando o iv com SecureRandom
        System.out.print("Gerando IV \t-> ");
        ivSpec = Utils.createCtrIvForAES(1, random);
        System.out.println("IV \t= " + Hex.encodeHexString(ivSpec.getIV()));
        // TODO - Externalizar trecho de código - FIM
    }

    public String createMasterPassword() {
        PBKDF2UtilBCFIPS pbkbf2 = new PBKDF2UtilBCFIPS();
        /*TODO - Armazenar em arquivo*/
        String masterPassword = "";
        String salt = "";
        String password = Utils.getStringFromInput("Digite uma senha mestre: ");

        try {
            salt = pbkbf2.getSalt();
            System.out.println("Salt gerado para senha mestre: " + salt);
            masterPassword = pbkbf2.generateDerivedKey(password, salt);
            System.out.println("Senha mestre cifrada: " + masterPassword);
            return masterPassword;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public String sendMessage(String receiverName, String message) {
        String encryptedMessage = "";

        try {
            try {
                initCrypto();
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            }

            encryptedMessage = AESwithCTR.getInstance().encrypt(message, aesKey, ivSpec);
            System.out.println("Mensagem cifrada enviada = " + encryptedMessage);
            System.out.println("Mensagem original = " + message);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return encryptedMessage;
    }

    public String readMessage(String message) {
        String decodeMessage = "";

        try {
            decodeMessage = AESwithCTR.getInstance().decrypt(message, aesKey, ivSpec);
            System.out.println("Mensagem original cifrada recebida = " + message);
            System.out.println("Mensagem decifrada = " + decodeMessage);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return decodeMessage;
    }
}
