package org.drasyl.cli;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.KeyPair;
import org.drasyl.identity.IdentitySecretKey;
import org.drasyl.node.identity.IdentityManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.drasyl.util.ArrayUtil;
import org.drasyl.util.ImmutableByteArray;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class X509_certification {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // let bouncycastle create the key material and put it in the drasyl identity later
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPairED25519.getPrivate();
        PublicKey publicKey = keyPairED25519.getPublic();

        // get ed25519 KeyPair from Identity
        Identity ID = IdentityManager.readIdentityFile(new File("drasyl.identity").toPath());
        KeyPair<IdentityPublicKey, IdentitySecretKey> keyPair = ID.getIdentityKeyPair();
        ImmutableByteArray publicKeyBytes = keyPair.getPublicKey().getBytes();
        ImmutableByteArray privateKeyBytes = keyPair.getSecretKey().getBytes();

        // convert KeyPair into java.security.Private- & PublicKey
        KeyFactory keyFactory = KeyFactory.getInstance("ed25519");
        PKCS8EncodedKeySpec keySpec0 = new PKCS8EncodedKeySpec(privateKeyBytes.getArray());
        //PrivateKey privateKey = keyFactory.generatePrivate(keySpec0);
        X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec(publicKeyBytes.getArray());
        //PublicKey publicKey = keyFactory.generatePublic(keySpec1);

        // create infos for X.509 certificate
        X500Name issuerName = new X500Name("CN=IssuerID");
        X500Name subjectName = new X500Name("CN=10.1.0.0/24");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // a day before
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year later

        // subject public key info

        // create certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, subjectName, publicKey);

        // define & add custom extension for the ipSubnet address
        //String customExtensionOID = "1.2.3.4.5"; // TODO: replace with custom OID
        // define custom extension content (e.g., IP subnet as a string)
        //String ipSubnet = "10.1.0.0/24"; // TODO: set right subnet address
        //byte[] extensionValue = ipSubnet.getBytes(); // convert subnet string to bytes
        //certBuilder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier(customExtensionOID), false, extensionValue);

        // create & add an issuer alternative name for the CA IP address
        //String caIP = "10.0.0.0"; // TODO: change to right IP address of the CA
        //GeneralName caIPGeneralName = new GeneralName(GeneralName.iPAddress, caIP);
        //GeneralNames issuerAltName = new GeneralNames(caIPGeneralName);
        //certBuilder.addExtension(Extension.issuerAlternativeName, false, issuerAltName);

        // create & add a subject alternative name (SAN) for the controller IP address
        //String controllerIP = "10.1.0.0"; // TODO: change to right IP address of the controller
        //GeneralName conIPGeneralName = new GeneralName(GeneralName.iPAddress, controllerIP);
        //GeneralNames subjectAltName = new GeneralNames(conIPGeneralName);
        //certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the certificate
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        System.out.println("X.509 certificate generated!");
        System.out.println(certificate);
    }
}
