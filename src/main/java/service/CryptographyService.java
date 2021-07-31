package service;


import de.rtner.security.auth.spi.PBKDF2;
import model.User;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import utils.AESwithCTR;
import utils.PBKDF2UtilBCFIPS;
import utils.Utils;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
    private int ivCounter = 0;
    private PBKDF2UtilBCFIPS pbkbf2;

    public CryptographyService(){
        this.random = new SecureRandom();
        this.pbkbf2 = new PBKDF2UtilBCFIPS();
    }

    private IvParameterSpec generateIv(){
        this.ivSpec = Utils.createCtrIvForAES(getIvCounter()+1, random);
        System.out.println("IV da mensagem: \t= " + Hex.encodeHexString(ivSpec.getIV()));

        //TODO: salvar iv no arquivo cifrado

        return ivSpec;
    }

    private void generateAESKey(){

        //TODO: buscar senha mestra no arquivo
        String masterKey = "teste";

        try {
            try {
                aesKey = new SecretKeySpec(Hex.decodeHex(PBKDF2UtilBCFIPS.generateDerivedKey(masterKey, pbkbf2.getSalt()).toCharArray()), "AES");
                System.out.println("Chave da mensagem: " + Hex.encodeHexString(aesKey.getEncoded()));
            } catch (DecoderException e) {
                throw new RuntimeException("Erro ao gerar chave AES: " + e.getMessage());
            }

        } catch (NoSuchAlgorithmException e) {
           throw new RuntimeException("Erro ao gerar salt: " + e.getMessage());
        }
    }

    public void createMasterPassword(String masterKey) {
        String salt = "";

        try {
            salt = pbkbf2.getSalt();
            System.out.println("Salt gerado para senha mestre: " + salt);
            String encryptedMasterKey = pbkbf2.generateDerivedKey(masterKey, salt);
            System.out.println("Senha mestre cifrada: " + encryptedMasterKey); // TODO: verificar se há necessidade de exibir a senha cifrada.
            saveEncryptedMasterKey(encryptedMasterKey);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Erro ao encriptar a senha mestre: " + ex.getMessage());
        }
    }

    // TODO: Persistir a senha mestre encriptada em um arquivo encriptado.
    private void saveEncryptedMasterKey(String encryptedMasterKey) {
        System.out.println("Salvando senha mestra em arquivo encriptado...");

        System.out.println("Senha mestra salva com sucesso!");
    }

    // TODO: Buscar senha mestre encriptada no arquivo encriptado
    private String getEncryptedMasterKey() {
        System.out.println("Buscando senha mestre em arquivo encriptado...");

        System.out.println("Senha encontrada com sucesso!");
        return "";
    }

    public void sendMessageToEncryptor(User sender, User receiver, String message) {
        System.out.println(sender.getName() + " fala para " + receiver.getName() + ": " + message);

        String encryptedMessage = encryptMessage(message);

        //TODO: Fazer o encrypt-then-Mac antes e enviar ao para decrypt
        calculateMac(message);

        sendMessageToDecryptor(encryptedMessage);
    }

    private String encryptMessage(String message) {
        String encryptedMessage;

        generateAESKey();
        generateIv();

        try {
            encryptedMessage = AESwithCTR.getInstance().encrypt(message, aesKey, ivSpec);
            System.out.println("Mensagem cifrada enviada = " + encryptedMessage);
            return encryptedMessage;
        } catch (NoSuchPaddingException|NoSuchAlgorithmException|NoSuchProviderException e) {
            throw new RuntimeException("Erro ao encriptar a mensagem: " + e.getMessage());
        }
    }

    public void sendMessageToDecryptor(String message) {
        recalculateMac();
        decryptMessage(message);
    }

    // TODO: calcular o MAC e verificar se está correto
    private void calculateMac(String message) {

    }

    //TODO: recalcular Mac para verificar autenticidade
    private void recalculateMac(){

    }

    private void decryptMessage(String message) {
        try {
            //TODO: aesKey e ivSpec devem vir do arquivo cifrado
            String decodeMessage = AESwithCTR.getInstance().decrypt(message, aesKey, ivSpec);
            System.out.println("Mensagem original cifrada recebida = " + message);
            System.out.println("Mensagem decifrada = " + decodeMessage);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Erro ao descriptografar a mensagem: " + ex.getMessage());
        }
    }

    public int getIvCounter() {
        return ivCounter;
    }
}
