package org.securefile.app;

import org.securefile.io.FileDecryptor;
import org.securefile.io.FileEncryptor;

import java.io.Console;
import java.nio.file.Path;

public class MainApp {

    public static void main(String[] args) {

        if (args.length != 3) {
            System.out.println("Usage:");
            System.out.println("  encrypt <inputFile> <outputFile>");
            System.out.println("  decrypt <inputFile> <outputFile>");
            return;
        }

        String mode = args[0];
        Path inputFile = Path.of(args[1]);
        Path outputFile = Path.of(args[2]);

        Console console = System.console();
        if (console == null) {
            System.err.println("No console available");
            return;
        }

        char[] password = console.readPassword("Enter password: ");

        try {
            if ("encrypt".equalsIgnoreCase(mode)) {
                new FileEncryptor().encryptFile(inputFile, outputFile, password);
                System.out.println("File encrypted successfully.");
            } else if ("decrypt".equalsIgnoreCase(mode)) {
                new FileDecryptor().decryptFile(inputFile, outputFile, password);
                System.out.println("File decrypted successfully.");
            } else {
                System.out.println("Unknown mode: " + mode);
            }
        } catch (Exception e) {
            System.err.println("Operation failed.");
        }
    }

}
