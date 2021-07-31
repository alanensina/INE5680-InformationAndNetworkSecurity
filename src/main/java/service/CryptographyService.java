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
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptographyService {

    private final String MASTERKEY = "MasterKey";
    private final String IV = "IV";
    private final String KEY = "Key";

    private String keystoreFile = "keystore.bcfks";
    private SecureRandom random;
    private int ivCounter = 0;
    private PBKDF2UtilBCFIPS pbkbf2;
    private KeyStore ks;

    public CryptographyService() {
        this.random = new SecureRandom();
        this.pbkbf2 = new PBKDF2UtilBCFIPS();
        try {
            this.ks = KeyStore.getInstance("BCFKS", "BCFIPS");
        } catch (KeyStoreException | NoSuchProviderException e) {
            throw new RuntimeException("Erro ao inicializar o KeyStore: " + e.getMessage());
        }
    }

    private IvParameterSpec generateIv() {
        IvParameterSpec iv = Utils.createCtrIvForAES(getIvCounter() + 1, random);
        System.out.println("IV da mensagem: \t= " + Hex.encodeHexString(iv.getIV()));

        saveNewEntryToEncryptedFile(IV, Hex.encodeHexString(iv.getIV()));

        return iv;
    }

    private Key generateAESKey() {
        String masterKey = getEncryptedMasterKey();

        if (Objects.isNull(masterKey)) {
            throw new RuntimeException("MasterKey não encontrada.");
        }

        //TODO: retirar esse sout quando finalizar o projeto, usado apenas para testes
        System.out.println("MasterKey retornada do arquivo encriptado: " + masterKey);

        try {
            try {
                Key key = new SecretKeySpec(Hex.decodeHex(PBKDF2UtilBCFIPS.generateDerivedKey(masterKey, pbkbf2.getSalt()).toCharArray()), "AES");
                System.out.println("Chave da mensagem: " + Hex.encodeHexString(key.getEncoded()));
                saveNewEntryToEncryptedFile(KEY, Hex.encodeHexString(key.getEncoded()));
                return key;
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

    private void saveEncryptedMasterKey(String encryptedMasterKey) {
        System.out.println("Salvando senha mestra em arquivo encriptado...");

        try {
            ks.load(null, null); // Cria arquivo vazio encriptado
            ks.store(new FileOutputStream(keystoreFile), null); // Salva o arquivo encriptado na raiz do sistema
            saveNewEntryToEncryptedFile(MASTERKEY, encryptedMasterKey); // Adiciona a masterkey como entrada no arquivo.
            ks.store(new FileOutputStream(keystoreFile), null);
            System.out.println("Senha mestra salva com sucesso!");
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException("Erro ao salvar senha mestra em arquivo encriptado: " + e.getMessage());
        }
    }

    private void saveNewEntryToEncryptedFile(String entryName, String encriptedKey) {
        try {
            Key key = new SecretKeySpec(Hex.decodeHex(encriptedKey.toCharArray()), "AES");
            ks.setKeyEntry(entryName, key, null, null);
            System.out.println(entryName + " salva no arquivo encriptado.");
        } catch (KeyStoreException | DecoderException e) {
            throw new RuntimeException("Erro ao salvar uma nova entrada no arquivo encriptado: " + e.getMessage());
        }
    }

    private String getEncryptedMasterKey() {
        String masterKey;
        System.out.println("Buscando senha mestre em arquivo encriptado...");
        try {
            Key key = ks.getKey(MASTERKEY, null);
            masterKey = Hex.encodeHexString(key.getEncoded());
            System.out.println("Senha encontrada com sucesso!");

            return masterKey;
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao buscar senha mestra no arquivo encriptado: " + e.getMessage());
        }
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

        Key key = generateAESKey();
        IvParameterSpec IV = generateIv();

        try {
            encryptedMessage = AESwithCTR.getInstance().encrypt(message, key, IV);
            System.out.println("Mensagem cifrada enviada = " + encryptedMessage);
            return encryptedMessage;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
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
    private void recalculateMac() {

    }

    private void decryptMessage(String message) {
        try {
            // Busca IV e key do arquivo cifrado
            Key ivKey = ks.getKey(IV, null);
            Key key = ks.getKey(KEY, null);
            IvParameterSpec iv = new IvParameterSpec(ivKey.getEncoded());

            //TODO: retirar esse sout quando finalizar o projeto, usado apenas para testes
            System.out.println("IV retornada do arquivo: " + Hex.encodeHexString(iv.getIV()));
            System.out.println("Key retornada do arquivo: " + Hex.encodeHexString(key.getEncoded()));

            String decodeMessage = AESwithCTR.getInstance().decrypt(message, key, iv);
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
