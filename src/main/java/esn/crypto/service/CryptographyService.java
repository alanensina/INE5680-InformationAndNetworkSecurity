package esn.crypto.service;


import esn.crypto.model.LittlePackage;
import esn.crypto.model.User;
import esn.crypto.utils.AESwithCTR;
import esn.crypto.utils.PBKDF2UtilBCFIPS;
import esn.crypto.utils.Utils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptographyService {
    private static final String PBKDF_2_WITH_HMAC_SHA_512 = "PBKDF2WithHmacSHA512";
    private static final String H_MAC_SHA_256 = "HMacSHA256";
    private static final String KEYSTORE_FILE = "keystore.bcfks";
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
            CryptoServicesRegistrar.setSecureRandom(FipsDRBG.SHA512_HMAC.fromEntropySource(new BasicEntropySourceProvider(new SecureRandom(), true)).build(null, false));
            this.ks = KeyStore.getInstance("BCFKS", "BCFIPS");
            this.mac = Mac.getInstance("HMacSHA256", "BCFIPS");
            this.cipher = Cipher.getInstance("AES/CTR/NoPadding", "BCFIPS");
            this.wrapCipher = Cipher.getInstance("AESKW", "BCFIPS");
            this.ks.load(null, null);
            this.ks.store(new FileOutputStream(KEYSTORE_FILE), null);
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | NoSuchPaddingException | CertificateException | IOException e) {
            throw new RuntimeException("Error starting the CryptographyService: " + e.getMessage());
        }
    }

    private IvParameterSpec generateIv() {
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(getIvCounter() + 1, random);
        System.out.println("IV's message: " + Hex.encodeHexString(ivSpec.getIV()));
        Key ivKey = new SecretKeySpec(ivSpec.getIV(), "AES");

        byte[] iv = createWrappedKey(ivKey);
        saveNewEntryToEncryptedFile(IV, Hex.encodeHexString(iv));

        return ivSpec;
    }

    private Key generateAESKey() {
        String masterKey = getEncryptedMasterKey();

        try {
            Key key = new SecretKeySpec(Hex.decodeHex(PBKDF2UtilBCFIPS.generateDerivedKey(masterKey, pbkbf2.getSalt()).toCharArray()), "AES");
            System.out.println("Message's key: " + Hex.encodeHexString(key.getEncoded()));
            byte[] wrappedKey = createWrappedKey(key);
            saveNewEntryToEncryptedFile(KEY, Hex.encodeHexString(wrappedKey));
            return key;
        } catch (NoSuchAlgorithmException | DecoderException e) {
            throw new RuntimeException("Error creating the AES key: " + e.getMessage());
        }
    }

    public void createMasterPassword(String masterKey) {
        try {
            String salt = pbkbf2.getSalt();
            System.out.println("Salt created to MasterKey: " + salt);
            String encryptedMasterKey = pbkbf2.generateDerivedKey(masterKey, salt);
            System.out.println("MasterKey encrypted: " + encryptedMasterKey);
            saveNewEntryToEncryptedFile(MASTER_KEY, encryptedMasterKey);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Error creating the MasterKey: " + ex.getMessage());
        }
    }

    private void saveNewEntryToEncryptedFile(String entryName, String encriptedKey) {
        try {
            Key key = new SecretKeySpec(Hex.decodeHex(encriptedKey.toCharArray()), "AES");
            ks.setKeyEntry(entryName, key, null, null);
            System.out.println(entryName + " stored in encrypted file.");
        } catch (KeyStoreException | DecoderException e) {
            throw new RuntimeException("Error storing the key in encrypted file: " + e.getMessage());
        }
    }

    private String getEncryptedMasterKey() {
        try {
            Key key = ks.getKey(MASTER_KEY, null);
            return Hex.encodeHexString(key.getEncoded());
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error to return the MasterKey from encrypted file: " + e.getMessage());
        }
    }

    public LittlePackage encryptMessageAndSendToDecryptor(User sender, User receiver, String message) {
        System.out.println(sender.getName() + " say to " + receiver.getName() + ": " + message);
        String encryptedMessage = encryptMessage(message);
        return encryptThenMac(encryptedMessage);
    }

    private String encryptMessage(String message) {
        Key key = generateAESKey();
        IvParameterSpec IV = generateIv();

        try {
            String encryptedMessage = AESwithCTR.getInstance().encrypt(message, key, IV);
            System.out.println("Encrypted message sent: " + encryptedMessage);
            return encryptedMessage;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Error encrypting the message: " + e.getMessage());
        }
    }

    private void receiveMessage(LittlePackage littlePackage) {
        recalculateMac(littlePackage);
        decryptMessage(littlePackage.getEncryptedMessage());
    }

    private LittlePackage encryptThenMac(String message) {
        try {
            Key key = unwrapKey(KEY);
            IvParameterSpec iv = new IvParameterSpec(unwrapKey(IV).getEncoded());

            Key masterKey = ks.getKey(MASTER_KEY, null);
            Key macKey = new SecretKeySpec(masterKey.getEncoded(), H_MAC_SHA_256);
            System.out.println("MAC-Key: " + Hex.encodeHexString(macKey.getEncoded()));

            byte[] macKeyWrapped = createWrappedKey(macKey);

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
            throw new RuntimeException("Error on encrypt-then-mac: " + e.getMessage());
        }
    }

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

            System.out.println("It's a MAC valid? " + (verifyMac(messageMac) ? "Yes" : "No"));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    private boolean verifyMac(byte[] messageMac) {
        return MessageDigest.isEqual(mac.doFinal(), messageMac);
    }

    private void decryptMessage(String encryptedMessage) {
        try {
            IvParameterSpec iv = new IvParameterSpec(unwrapKey(IV).getEncoded());
            Key key = unwrapKey(KEY);
            String decryptedMessage = AESwithCTR.getInstance().decrypt(encryptedMessage, key, iv);
            System.out.println("Encrypted message received: " + encryptedMessage);
            System.out.println("Decrypted message: " + decryptedMessage);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
            throw new RuntimeException("Error decrypting the message: " + ex.getMessage());
        }
    }

    public int getIvCounter() {
        return ivCounter;
    }

    private byte[] createWrappedKey(Key keyToWrap) {
        try {
            Key masterKey = ks.getKey(MASTER_KEY, null);
            wrapCipher.init(Cipher.WRAP_MODE, masterKey);
            byte[] wrappedKey = wrapCipher.wrap(keyToWrap);
            System.out.println("Wrapped key created: " + Hex.encodeHexString(wrappedKey));
            return wrappedKey;
        } catch (InvalidKeyException | IllegalBlockSizeException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error creating Wrapped Key: " + e.getMessage());
        }
    }

    private SecretKey unwrap(Key wrappedKey, String algorithm) {
        try {
            Key masterKey = ks.getKey(MASTER_KEY, null);
            wrapCipher.init(Cipher.UNWRAP_MODE, masterKey);
            return (SecretKey) wrapCipher.unwrap(wrappedKey.getEncoded(), algorithm, Cipher.SECRET_KEY);
        } catch (InvalidKeyException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Error unwrapping the key: " + e.getMessage());
        }
    }

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
                    throw new RuntimeException("Unwrap type not found");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error unwrapping the " + type + ": " + e.getMessage());
        }
    }

    public void send(LittlePackage littlePackage) {
        receiveMessage(littlePackage);
    }
}
