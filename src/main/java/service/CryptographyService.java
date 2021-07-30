package service;


import model.User;
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
    private SecureRandom random;

    public void initCrypto() throws NoSuchAlgorithmException, NoSuchProviderException {
        // TODO - Externalizar trecho de código - INICIO
        // Gera uma chave AES
        random = new SecureRandom();
        System.out.print("Gerando chave \t-> ");
        aesKey = Utils.createKeyForAES(128, random);
        System.out.println("Chave AES \t= " + Hex.encodeHexString(aesKey.getEncoded()));

        // Gerando o iv com SecureRandom
        System.out.print("Gerando IV \t-> ");
        ivSpec = Utils.createCtrIvForAES(1, random);
        System.out.println("IV \t= " + Hex.encodeHexString(ivSpec.getIV()));
        // TODO - Externalizar trecho de código - FIM
    }

    public void createMasterPassword(String masterKey) {
        PBKDF2UtilBCFIPS pbkbf2 = new PBKDF2UtilBCFIPS();
        String salt = "";

        try {
            salt = pbkbf2.getSalt();
            System.out.println("Salt gerado para senha mestre: " + salt);
            String encryptedMasterKey =  pbkbf2.generateDerivedKey(masterKey, salt);
            System.out.println("Senha mestre cifrada: " + encryptedMasterKey); // TODO: verificar se há necessidade de exibir a senha cifrada.
            saveEncryptedMasterKey(encryptedMasterKey);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Erro ao encriptar a senha mestre.");
        }
    }

    // TODO: Persistir a senha mestre encriptada em um arquivo encriptado.
    private void saveEncryptedMasterKey(String encryptedMasterKey){
        System.out.println("Salvando senha mestra em arquivo encriptado...");

        System.out.println("Senha mestra salva com sucesso!");
    }

    // TODO: Buscar senha mestre encriptada no arquivo encriptado
    private String getEncryptedMasterKey(){
        System.out.println("Buscando senha mestre em arquivo encriptado...");

        System.out.println("Senha encontrada com sucesso!");
        return "";
    }

    public String sendMessage(User sender, User receiver, String message) {
        String encryptedMessage = "";
        System.out.println(sender.getName() + " fala para " + receiver.getName() + ": " + message);

        try {
            try {
                initCrypto();
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            }

            encryptedMessage = AESwithCTR.getInstance().encrypt(message, aesKey, ivSpec);
            System.out.println("Mensagem cifrada enviada = " + encryptedMessage);
           // System.out.println("Mensagem original = " + message);
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
