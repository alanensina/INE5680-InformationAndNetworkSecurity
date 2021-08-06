package app;

import model.LittlePackage;
import model.User;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import service.CryptographyService;

import java.security.Security;
import java.util.Objects;
import java.util.Scanner;

public class Crypto {

    private final static String EXIT = "exit";

    private User user1;
    private User user2;
    private CryptographyService service;
    private Scanner scanner;

    public Crypto() {
        this.scanner = new Scanner(System.in);
        System.out.println("Insert the master key: ");
        this.service = new CryptographyService();
        service.createMasterPassword(scanner.nextLine());
    }

    public static void main(String[] args) {
        initBCFIPS();
        Crypto crypto = new Crypto();
        crypto.start();
    }

    private static void initBCFIPS() {
        Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            throw new RuntimeException("Bouncy Castle Provider unavailable.");
        } else {
            System.out.println("Bouncy Castle Provider started!");
        }
    }

    private void start() {
        System.out.println("Insert the name of the first user: ");
        this.user1 = new User(scanner.nextLine());

        System.out.println("Insert the name of the second user: ");
        this.user2 = new User(scanner.nextLine());

        if (Objects.isNull(user1) || Objects.isNull(user2)) {
            throw new RuntimeException("Names not informed.");
        }

        startChat(user1, user2);
    }

    private void startChat(User user1, User user2) {
        String msg;
        LittlePackage littlePackage;

        while (true) {
            System.out.println("Waiting " + user1 + " type the message...");
            msg = scanner.nextLine();
            checkExitMessage(msg);
            littlePackage = service.encryptMessageAndSendToDecryptor(user1, user2, msg);
            service.send(littlePackage);

            System.out.println("Waiting " + user2 + " type the message...");
            msg = scanner.nextLine();
            checkExitMessage(msg);
            littlePackage = service.encryptMessageAndSendToDecryptor(user2, user1, msg);
            service.send(littlePackage);
        }
    }

    private void checkExitMessage(String message) {
        if (EXIT.equalsIgnoreCase(message)) {
            System.out.println("Chat closed!");
            this.scanner.close();
            System.exit(0);
        }
    }
}
