package app;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import service.CryptographyService;

import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Crypto {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {

        int addProvider = Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            System.out.println("Bouncy Castle provider NAO disponivel");
        } else {
            System.out.println("Bouncy Castle provider esta disponivel");
        }

        CryptographyService cryptographyService = new CryptographyService();
        String encryptedMessage = cryptographyService.sendMessage("jesus", "send me from hell");
        cryptographyService.readMessage(encryptedMessage);
    }
}
