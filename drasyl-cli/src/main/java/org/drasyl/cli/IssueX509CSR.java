package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

public class IssueX509CSR {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // generate the keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPairED25519.getPrivate();
        PublicKey publicKey = keyPairED25519.getPublic();

        // save the keys to files
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        writeKeyToFile("PRIVATE KEY", privateKeyInfo.getEncoded(), "controller_ed25519_private.key");
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        writeKeyToFile("PUBLIC KEY", publicKeyInfo.getEncoded(), "controller_ed25519_public.pem");

        // create only subject info for future certificate
        X500Name subjectName = new X500Name(createSubjectString());

        // create CSR builder
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectName, publicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the CSR
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        System.out.println("CSR generated.");
        writeCSRToFile(csr);
        System.out.println("CSR saved successfully.");
    }

    private static String createSubjectString() {
        String subjectCN = "10.1.0.0/16"; //here used for the subnet TODO: change to right subnet
        String subjectOrganizationName = "subjectO"; //TODO: change to right organization name
        String subjectOrganizationUnitName = "subjectOU"; //TODO: change to right organization unit name
        String subjectCountry = "subjectC"; //TODO: change to right country code
        String subjectState = "subjectST"; //TODO: change to right state code
        String subjectLocation = "subjectL"; //TODO: change to right location
        return "CN=" + subjectCN + ", O=" + subjectOrganizationName + ", OU=" + subjectOrganizationUnitName + ", C=" + subjectCountry + ", ST=" + subjectState + ", L=" + subjectLocation;
    }

    private static void writeCSRToFile(PKCS10CertificationRequest csr) throws IOException {
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter("controllerCSR.csr"));
        pemWriter.writeObject(csr);
        pemWriter.close();
    }

    private static void writeKeyToFile(String description, byte[] keyBytes, String filename) throws IOException {
        PemObject pemObjectPublicKey = new PemObject(description, keyBytes);
        PemWriter pemWriterPublicKey = new PemWriter(new FileWriter(filename));
        pemWriterPublicKey.writeObject(pemObjectPublicKey);
        pemWriterPublicKey.close();
    }
}
