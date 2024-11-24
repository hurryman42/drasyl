package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class GenerateIdentity {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        // generate the keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPairED25519.getPrivate();
        PublicKey publicKey = keyPairED25519.getPublic();

        // save the keys to files
        String publicKeyFileName = args[0];
        String privateKeyFileName = args[1];
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        writeKeyToFile("PUBLIC KEY", publicKeyInfo.getEncoded(), publicKeyFileName + ".pem");
        writeKeyToFile("PRIVATE KEY", privateKeyInfo.getEncoded(), privateKeyFileName + ".key");

        // TODO: generate identity with the keys
    }

    private static void writeKeyToFile(String description, byte[] keyBytes, String filename) throws IOException {
        PemObject pemObjectPublicKey = new PemObject(description, keyBytes);
        PemWriter pemWriterPublicKey = new PemWriter(new FileWriter(filename));
        pemWriterPublicKey.writeObject(pemObjectPublicKey);
        pemWriterPublicKey.close();
    }
}
