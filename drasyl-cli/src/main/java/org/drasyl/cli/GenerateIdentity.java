package org.drasyl.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class GenerateIdentity {
    /**
     * Generates a ED25519 key pair, saves it into two PEM files and uses it to create a drasyl Identity
     *
     * @param args a string array consisting of the file names for the to be created public and private key (without file endings)
     * @throws IOException thrown when something goes wrong with reading the files
     * @throws NoSuchAlgorithmException thrown when the desired algorithm cannot be found
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        String publicKeyFileName = args[0];
        String privateKeyFileName = args[1];

        // generate the keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPairED25519.getPrivate();
        PublicKey publicKey = keyPairED25519.getPublic();

        // save the keys to files
        writeKeyToFile("PUBLIC KEY", publicKey.getEncoded(), publicKeyFileName + ".pem");
        writeKeyToFile("PRIVATE KEY", privateKey.getEncoded(), privateKeyFileName + ".key");

        // TODO: generate Identity with the keys
    }

    private static void writeKeyToFile(String description, byte[] keyBytes, String filename) throws IOException {
        PemObject pemObjectPublicKey = new PemObject(description, keyBytes);
        PemWriter pemWriterPublicKey = new PemWriter(new FileWriter(filename));
        pemWriterPublicKey.writeObject(pemObjectPublicKey);
        pemWriterPublicKey.close();
    }
}
