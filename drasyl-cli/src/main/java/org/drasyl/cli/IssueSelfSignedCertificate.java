package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * generates a self-signed X.509 certificate, given the file paths to an ed25519 key pair and the location the certificate should be saved to
 */
public class IssueSelfSignedCertificate {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final String publicKeyFilePath = args[0];
        final String privateKeyFilePath = args[1];
        final String certificateFilePath = args[2];

        // load keys
        final PublicKey publicKey = loadPublicKey(publicKeyFilePath);
        final PrivateKey privateKey = loadPrivateKey(privateKeyFilePath);

        // create infos for X.509 certificate
        final X500Name issuerAndSubjectName = new X500Name("CN=drasylCA, O=drasyl, C=DE, ST=HH, L=Hamburg");
        final BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        final Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
        final Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

        // create certificate builder
        final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerAndSubjectName, serialNumber, notBefore, notAfter, issuerAndSubjectName, publicKey);
        // create a content signer
        final ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the certificate
        final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        writeCertificateToFile(certificate, certificateFilePath);
        System.out.println("X.509 certificate generated and saved successfully!");
        System.out.println(certificate);
    }

    private static void writeCertificateToFile(X509Certificate certificate, String certificateFilePath) throws IOException {
        final JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certificateFilePath));
        pemWriter.writeObject(certificate);
        pemWriter.close();
    }

    private static PrivateKey loadPrivateKey(String privateKeyFilePath) throws IOException {
        final PEMParser pemParser = new PEMParser(new FileReader(privateKeyFilePath));
        final PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
        pemParser.close();
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPrivateKey(keyInfo);
    }

    private static PublicKey loadPublicKey(String publicKeyFilePath) throws IOException {
        final PEMParser pemParser = new PEMParser(new FileReader(publicKeyFilePath));
        final SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
        pemParser.close();
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPublicKey(keyInfo);
    }
}
