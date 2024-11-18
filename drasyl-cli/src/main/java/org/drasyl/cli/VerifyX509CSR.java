package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;

public class VerifyX509CSR {
    public static void main(String[] args) throws IOException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());

        // load CSR file
        PEMParser pemParserCSR = new PEMParser(new FileReader("controllerCSR.csr"));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParserCSR.readObject();
        pemParserCSR.close();
        // get public key
        SubjectPublicKeyInfo controllerPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PublicKey controllerPublicKey = converter.getPublicKey(controllerPublicKeyInfo);
        // get subject
        X500Name csrSubject = csr.getSubject();
        System.out.println("Subject of the CSR is: " + csrSubject);

        // TODO: check if subject has the right subnet address

        // load CA's private key
        PEMParser pemParserPrivateKey = new PEMParser(new FileReader("ca_ed25519_private.key"));
        PrivateKeyInfo caPrivateKeyInfo = (PrivateKeyInfo) pemParserPrivateKey.readObject();
        pemParserPrivateKey.close();
        PrivateKey caPrivateKey = converter.getPrivateKey(caPrivateKeyInfo);
        System.out.println(caPrivateKey);

        /*
        try {
            Signature signature = Signature.getInstance(csr.getSignatureAlgorithm().getAlgorithm().getId(), "BC");
            signature.initVerify(controllerPublicKey);
            signature.update(csr.toASN1Structure().getCertificationRequestInfo().getEncoded());
            signature.verify(csr.getSignature());
        } catch (Exception e) {
            throw new SignatureException("Error verifying CSR signature: " + e.getMessage(), e);
        }*/

        // create infos for the new X509 certificate
        X500Name issuerName = new X500Name("CN=drasylCA, O=drasyl, C=DE, ST=HH, L=Hamburg");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

        // create certificate builder (subject taken from CSR)
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, csrSubject, controllerPublicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(caPrivateKey);
        // build the certificate
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        saveCertificateToFile(certificate);
    }

    private static void saveCertificateToFile(X509Certificate certificate) throws IOException, CertificateEncodingException {
        String beginString = "-----BEGIN CERTIFICATE-----\n";
        String endString = "\n-----END CERTIFICATE-----\n";
        String certString = beginString + Base64.getEncoder().encodeToString(certificate.getEncoded()) + endString;
        try (FileWriter fileWriter = new FileWriter("controllerCertificate.crt")) {
            fileWriter.write(certString);
        }
    }
}
