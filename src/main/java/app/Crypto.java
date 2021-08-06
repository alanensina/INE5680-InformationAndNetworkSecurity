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
        System.out.println("Insira a senha mestra: ");
        this.service = new CryptographyService();
        service.createMasterPassword(scanner.nextLine());
    }

    public static void main(String[] args) {
        initBCFIPS();
        Crypto crypto = new Crypto();
        crypto.start();
    }

    // Método responsável em iniciar o BCFIPS
    private static void initBCFIPS() {
        Security.addProvider(new BouncyCastleFipsProvider());

        if (Security.getProvider("BCFIPS") == null) {
            throw new RuntimeException("Bouncy Castle Provider indisponível.");
        } else {
            System.out.println("Bouncy Castle Provider inicializado!");
        }
    }

    // Método responsável em iniciar a aplicação
    private void start() {
        System.out.println("Insira o nome do primeiro usuário: ");
        this.user1 = new User(scanner.nextLine());

        System.out.println("Insira o nome do segundo usuário: ");
        this.user2 = new User(scanner.nextLine());

        if (Objects.isNull(user1) || Objects.isNull(user2)) {
            throw new RuntimeException("Nomes de usuários não informados.");
        }

        startChat(user1, user2);
    }

    // Método responsável em iniciar o chat
    private void startChat(User user1, User user2) {
        String msg;
        LittlePackage littlePackage;

        while (true) {
            System.out.println("Aguardando " + user1.getName() + " digitar a mensagem...");
            msg = scanner.nextLine();
            checkExitMessage(msg);
            littlePackage = service.encryptMessageAndSendToDecryptor(user1, user2, msg);
            service.send(littlePackage);

            System.out.println("Aguardando " + user2.getName() + " digitar a mensagem...");
            msg = scanner.nextLine();
            checkExitMessage(msg);
            littlePackage = service.encryptMessageAndSendToDecryptor(user2, user1, msg);
            service.send(littlePackage);
        }
    }

    // Método responsável em verificar
    private void checkExitMessage(String message) {
        if (EXIT.equalsIgnoreCase(message)) {
            System.out.println("Chat finalizado!");
            this.scanner.close();
            System.exit(0);
        }
    }
}
