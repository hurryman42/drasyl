package org.drasyl.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/**
 * generates a self-signed X.509 certificate (ed25519 keyPair is also generated)
 */
public class IssueX509Certificate {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // generate the keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPairED25519.getPrivate();
        PublicKey publicKey = keyPairED25519.getPublic();

        // save the keys to files
        saveKeyToFile(Base64.getEncoder().encodeToString(privateKey.getEncoded()), "ca_ed25519_private.key");
        saveKeyToFile(Base64.getEncoder().encodeToString(publicKey.getEncoded()), "ca_ed25519_public.pem");
        System.out.println("Keys saved successfully in Base64 format.");

        // use the generated keys to create a drasyl identity for the node
        /*Identity nodeID = //generate Identity with the ed25519 keys;
        //IdentityManager.writeIdentityFile(new File("node.identity").toPath(), nodeID);*/

        /* failed: get ed25519 KeyPair from Identity & convert it into java.security.Private- & PublicKey
        Identity ID = IdentityManager.readIdentityFile(new File("drasyl.identity").toPath());
        KeyPair<IdentityPublicKey, IdentitySecretKey> keyPair = ID.getIdentityKeyPair();
        ImmutableByteArray privateKeyBytes = keyPair.getSecretKey().getBytes();
        ImmutableByteArray publicKeyBytes = keyPair.getPublicKey().getBytes();
        KeyFactory keyFactory = KeyFactory.getInstance("ed25519");
        PKCS8EncodedKeySpec keySpec0 = new PKCS8EncodedKeySpec(privateKeyBytes.getArray());
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec0);
        X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec(publicKeyBytes.getArray());
        PublicKey publicKey = keyFactory.generatePublic(keySpec1); */

        // create infos for X.509 certificate
        X500Name issuerName = new X500Name("CN=drasylCA, O=drasyl, C=DE, ST=HH, L=Hamburg");
        X500Name subjectName = new X500Name(createSubjectString());
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

        // define & add custom extension for the ipSubnet address
        //String customExtensionOID = "1.2.3.4.5"; // TODO: replace with custom OID
        //String ipSubnet = "10.1.0.0/24"; // TODO: set right subnet address
        //byte[] extensionValue = ipSubnet.getBytes(); // convert subnet string to bytes
        //certBuilder.addExtension(new ASN1ObjectIdentifier(customExtensionOID), false, extensionValue);

        // create & add a subject alternative name (SAN) for the controller IP address
        //String controllerIP = "10.1.0.0"; // TODO: change to right IP address of the controller
        //GeneralName conIPGeneralName = new GeneralName(GeneralName.iPAddress, controllerIP);
        //GeneralNames subjectAltName = new GeneralNames(conIPGeneralName);
        //certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

        // create certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, subjectName, publicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the certificate
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        System.out.println("X.509 certificate generated!");
        System.out.println(certificate);
        saveCertificateToFile(certificate);
        System.out.println("Certificate saved successfully.");
    }

    private static void saveCertificateToFile(X509Certificate certificate) throws IOException, CertificateEncodingException {
        String beginString = "-----BEGIN CERTIFICATE-----\n";
        String endString = "\n-----END CERTIFICATE-----\n";
        String certString = beginString + Base64.getEncoder().encodeToString(certificate.getEncoded()) + endString;
        try (FileWriter fileWriter = new FileWriter("cacert.crt")) {
            fileWriter.write(certString);
        }
    }

    private static void saveKeyToFile(String keyString, String filename) throws IOException {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(keyString);
        }
    }

    private static String createSubjectString() {
        String subjectCN = "10.0.0.0/8"; //here used for the subnet TODO: change to right subnet
        String subjectOrganizationName = "subjectO"; //TODO: change to right organization name
        String subjectOrganizationUnitName = "subjectOU"; //TODO: change to right organization unit name
        String subjectCountry = "subjectC"; //TODO: change to right country code
        String subjectState = "subjectST"; //TODO: change to right state code
        String subjectLocation = "subjectL"; //TODO: change to right location
        return "CN=" + subjectCN + ", O=" + subjectOrganizationName + ", OU=" + subjectOrganizationUnitName + ", C=" + subjectCountry + ", ST=" + subjectState + ", L=" + subjectLocation;
    }
}
