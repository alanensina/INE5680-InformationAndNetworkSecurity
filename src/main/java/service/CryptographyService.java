package service;


import utils.AESwithCTR;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptographyService {
    public String sendMessage(String receiverName, String message) {
        String encryptedMessage = "";

        try {
            encryptedMessage = AESwithCTR.getInstance().encrypt(message);
            System.out.println("Mensagem cifrada = " + encryptedMessage);
            System.out.println("Mensagem original = " + message);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return encryptedMessage;
    }

    public String readMessage(String message) {
        String decodeMessage = "";

        try {
            decodeMessage = AESwithCTR.getInstance().decrypt(message);
            System.out.println("Mensagem cifrada = " + message);
            System.out.println("Mensagem decifrada = " + decodeMessage);
        } catch (Exception ex) {
            Logger.getLogger(CryptographyService.class.getName()).log(Level.SEVERE, null, ex);
        }

        return decodeMessage;
    }
}
