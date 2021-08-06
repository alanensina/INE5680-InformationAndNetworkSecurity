package utils;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PBKDF2UtilBCFIPS {

    private static PBKDF2UtilBCFIPS instance;

    public static PBKDF2UtilBCFIPS getInstance() {
        if (instance == null) {
            instance = new PBKDF2UtilBCFIPS();
        }
        return instance;
    }

    public static String generateDerivedKey(String password, String salt) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 5000, 128);
        SecretKeyFactory pbkdf2 = null;
        try {
            pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BCFIPS");
            SecretKey sk = pbkdf2.generateSecret(spec);
            return Hex.encodeHexString(sk.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Error generating the derived key: " + e.getMessage());
        }
    }

    public String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return Hex.encodeHexString(salt);
    }
}
