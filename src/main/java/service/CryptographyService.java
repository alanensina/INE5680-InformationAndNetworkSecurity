package service;

import model.LittlePackage;
import model.User;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;
import utils.AESwithCTR;
import utils.PBKDF2UtilBCFIPS;
import utils.Utils;

import javax.crypto.*;
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

    private static final String PBKDF_2_WITH_HMAC_SHA_512 = "PBKDF2WithHmacSHA512";
    private static final String H_MAC_SHA_256 = "HMacSHA256";
    private static final String  KEYSTORE_FILE = "keystore.bcfks";
    private static final String MASTER_KEY = "MasterKey";
    private static final String IV = "IV";
    private static final String KEY = "Key";
    private static final String MAC_KEY = "mac-key";

    private SecureRandom random;
    private int ivCounter = 0;
    private PBKDF2UtilBCFIPS pbkbf2;
    private KeyStore ks;
    private Mac mac;
    private Cipher cipher;
    private Cipher wrapCipher;

    public CryptographyService() {
        this.random = new SecureRandom();
        this.pbkbf2 = new PBKDF2UtilBCFIPS();
        try {
            // Adicionado para resolver problema da lentidao no Linux
            CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));
            this.ks = KeyStore.getInstance("BCFKS", "BCFIPS");
            this.mac = Mac.getInstance("HMacSHA256", "BCFIPS");
            this.cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            this.wrapCipher = Cipher.getInstance("AESKW", "BCFIPS");
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Erro ao inicializar o CryptographyService: " + e.getMessage());
        }
    }

    // Método responsável por gerar o IV
    private IvParameterSpec generateIv() {
        // Cria o IV da mensagem
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(getIvCounter() + 1, random);
        System.out.println("IV da mensagem: " + Hex.encodeHexString(ivSpec.getIV()));

        // Transforma o IV em uma Key
        Key ivKey = new SecretKeySpec(ivSpec.getIV(), "AES");

        // Aplica o Wrapped Key no IV
        byte[] iv = createWrappedKey(ivKey);
        saveNewEntryToEncryptedFile(IV, Hex.encodeHexString(iv));

        return ivSpec;
    }

    // Método responsável por criar uma Key derivando da chave-mestra
    private Key generateAESKey() {
        String masterKey = getEncryptedMasterKey();

        if (Objects.isNull(masterKey)) {
            throw new RuntimeException("MasterKey não encontrada.");
        }

        try {
            // Cria uma Key derivando da Senha Mestre
            Key key = new SecretKeySpec(Hex.decodeHex(PBKDF2UtilBCFIPS.generateDerivedKey(masterKey, pbkbf2.getSalt()).toCharArray()), "AES");
            System.out.println("Chave da mensagem: " + Hex.encodeHexString(key.getEncoded()));

            // Aplica a Wrapped Key na chave AES
            byte[] wrappedKey = createWrappedKey(key);

            // Salva a key no arquivo encriptado
            saveNewEntryToEncryptedFile(KEY, Hex.encodeHexString(wrappedKey));
            return key;
        } catch (NoSuchAlgorithmException | DecoderException e) {
            throw new RuntimeException("Erro ao gerar chave AES: " + e.getMessage());
        }
    }

    // Método responsável por criar a chave-mestra
    public void createMasterPassword(String masterKey) {
        String salt = "";

        try {
            salt = pbkbf2.getSalt();
            System.out.println("Salt gerado para senha mestre: " + salt);
            String encryptedMasterKey = pbkbf2.generateDerivedKey(masterKey, salt); // Cria a Chave Derivada (Wrapped Key) da Senha Mestra
            System.out.println("Senha mestre cifrada: " + encryptedMasterKey);
            saveEncryptedMasterKey(encryptedMasterKey);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Erro ao encriptar a senha mestre: " + ex.getMessage());
        }
    }

    // Método responsável por salvar no arquivo a chave-mestra
    private void saveEncryptedMasterKey(String encryptedMasterKey) {
        System.out.println("Salvando senha mestra em arquivo encriptado...");

        try {
            ks.load(null, null); // Cria arquivo vazio encriptado
            ks.store(new FileOutputStream(KEYSTORE_FILE), null); // Salva o arquivo encriptado na raiz do sistema
            saveNewEntryToEncryptedFile(MASTER_KEY, encryptedMasterKey); // Adiciona a masterkey como entrada no arquivo.
            ks.store(new FileOutputStream(KEYSTORE_FILE), null);
            System.out.println("Senha mestra salva com sucesso!");
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException("Erro ao salvar senha mestra em arquivo encriptado: " + e.getMessage());
        }
    }

    // Método responsável para salvar uma key no arquivo encriptado
    private void saveNewEntryToEncryptedFile(String entryName, String encriptedKey) {
        try {
            Key key = new SecretKeySpec(Hex.decodeHex(encriptedKey.toCharArray()), "AES");
            ks.setKeyEntry(entryName, key, null, null);
            System.out.println(entryName + " salva no arquivo encriptado.");
        } catch (KeyStoreException | DecoderException e) {
            throw new RuntimeException("Erro ao salvar uma nova entrada no arquivo encriptado: " + e.getMessage());
        }
    }

    // Método responsável para buscar a senha mestra no arquivo encriptado
    private String getEncryptedMasterKey() {
        String masterKey;
        System.out.println("Buscando senha mestre em arquivo encriptado...");
        try {
            Key key = ks.getKey(MASTER_KEY, null);
            masterKey = Hex.encodeHexString(key.getEncoded());
            System.out.println("Senha encontrada com sucesso!");

            return masterKey;
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao buscar senha mestra no arquivo encriptado: " + e.getMessage());
        }
    }

    // Método responsável para cifrar a mensagem e enviar ao decifrador
    public LittlePackage encryptMessageAndSendToDecryptor(User sender, User receiver, String message) {
        System.out.println(sender.getName() + " fala para " + receiver.getName() + ": " + message);

        // Cifra a mensagem e em seguida aplica o encrypt-then-mac e retorna o pacote que será enviado ao decifrador
        return encryptThenMac(encryptMessage(message));
    }

    // Método responsável por cifrar a mensagem
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

    // Método que recebe a mensagem enviada. É responsável por validar o MAC e decifrar a mensagem
    private void receiveMessage(LittlePackage littlePackage) {
        recalculateMac(littlePackage);
        decryptMessage(littlePackage.getEncryptedMessage());
    }

    // Método responsável por aplicar o encrypt-Then-Mac
    private LittlePackage encryptThenMac(String message) {
        try {
            // Aplica o unwrap do IV e da chave AES que estão no arquivo encriptado
            Key key = unwrapKey(KEY);
            IvParameterSpec iv = new IvParameterSpec(unwrapKey(IV).getEncoded());

            Key masterKey = ks.getKey(MASTER_KEY, null);
            Key macKey = new SecretKeySpec(masterKey.getEncoded(), H_MAC_SHA_256);
            System.out.println("Chave do MAC: " + Hex.encodeHexString(macKey.getEncoded()));

            // Aplica a Wrapped key na Mac Key
            byte[] macKeyWrapped = createWrappedKey(macKey);

            // Salva a Mac Key Wrapped no arquivo encriptado
            saveNewEntryToEncryptedFile(MAC_KEY, Hex.encodeHexString(macKeyWrapped));

            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] cipherText = new byte[cipher.getOutputSize(message.length() + mac.getMacLength())];

            int ctLength = cipher.update(Utils.toByteArray(message), 0, message.length(), cipherText, 0);
            mac.init(macKey);
            mac.update(Utils.toByteArray(message));

            ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);

            return new LittlePackage(ctLength, cipherText, message);

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException |
                InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
                IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Erro ao realizar o encrypt-then-mac: " + e.getMessage());
        }
    }

    // Método responsável por recalcular o MAC
    private void recalculateMac(LittlePackage littlePackage) {
        try {
            Key key = unwrapKey(KEY);
            Key macKey = unwrapKey(MAC_KEY);
            IvParameterSpec iv = new IvParameterSpec(unwrapKey(IV).getEncoded());

            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] plainText = cipher.doFinal(littlePackage.getCipherText(), 0, littlePackage.getCtLength());
            int messageLength = plainText.length - mac.getMacLength();

            mac.init(macKey);
            mac.update(plainText, 0, messageLength);

            byte[] messageMac = new byte[mac.getMacLength()];
            System.arraycopy(plainText, messageLength, messageMac, 0, messageMac.length);

            System.out.println("MAC válido? " + (verifyMac(messageMac) ? "Sim" : "Não"));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    // Método responsável por verificar se o MAC é válido ou não
    private boolean verifyMac(byte[] messageMac) {
        return MessageDigest.isEqual(mac.doFinal(), messageMac);
    }


    // Método responsável por decifrar a mensagem cifrada
    private void decryptMessage(String message) {
        try {
            IvParameterSpec iv = new IvParameterSpec(unwrapKey(IV).getEncoded());
            Key key = unwrapKey(KEY);

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

    // Método responsável para criar uma wrapped key
    private byte[] createWrappedKey(Key keyToWrap) {
        try {
            Key masterKey = ks.getKey(MASTER_KEY, null);
            wrapCipher.init(Cipher.WRAP_MODE, masterKey);
            byte[] wrappedKey = wrapCipher.wrap(keyToWrap);
            System.out.println("Wrapped key gerada: " + Hex.encodeHexString(wrappedKey));
            return wrappedKey;
        } catch (InvalidKeyException | IllegalBlockSizeException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao gerar Wrapped Key: " + e.getMessage());
        }
    }

    // Método responsável para realizar o unwrap de uma chave conforme o algoritmo indicado
    private SecretKey unwrap(Key wrappedKey, String algorithm) {
        try {
            Key masterKey = ks.getKey(MASTER_KEY, null);
            wrapCipher.init(Cipher.UNWRAP_MODE, masterKey);
            return (SecretKey) wrapCipher.unwrap(wrappedKey.getEncoded(), algorithm, Cipher.SECRET_KEY);
        } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao aplicar o Unwrap Key: " + e.getMessage());
        }
    }

    // Método responsável para realizar o Unwrap do IV, AES-key e mac-key
    private Key unwrapKey(String type) {
        Key key;
        try {
            switch (type) {
                case KEY:
                    key = ks.getKey(KEY, null);
                    return unwrap(key, PBKDF_2_WITH_HMAC_SHA_512);
                case MAC_KEY:
                    key = ks.getKey(MAC_KEY, null);
                    return unwrap(key, H_MAC_SHA_256);
                case IV:
                    key = ks.getKey(IV, null);
                    return unwrap(key, PBKDF_2_WITH_HMAC_SHA_512);
                default:
                    throw new RuntimeException("Tipo de unwrap não identificado.");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Erro ao aplicar o unwrap da chave " + type + ": " + e.getMessage());
        }
    }

    // Método responsável por enviar a o pacote da mensagem
    public void send(LittlePackage littlePackage) {
        receiveMessage(littlePackage);
    }
}