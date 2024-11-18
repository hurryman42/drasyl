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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class VerifyX509CSR {
    public static void main(String[] args) throws IOException, SignatureException, CertificateException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        // load CA's private key
        String caPrivateKeyFilePath = "ca_ed25519_private.key";
        PEMParser pemParser0 = new PEMParser(new FileReader(caPrivateKeyFilePath));
        PrivateKeyInfo caPrivateKeyInfo = (PrivateKeyInfo) pemParser0.readObject();
        pemParser0.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey caPrivateKey = converter.getPrivateKey(caPrivateKeyInfo);

        // load CSR file
        String csrFilePath = "controllerCSR.csr";
        PEMParser pemParser1 = new PEMParser(new FileReader(csrFilePath));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParser1.readObject();
        pemParser1.close();
        // get public key
        SubjectPublicKeyInfo publicKeyInfo = csr.getSubjectPublicKeyInfo();
        PublicKey controllerPublicKey = converter.getPublicKey(publicKeyInfo);
        // get subject
        X500Name csrSubject = csr.getSubject();
        System.out.println("Subject of the CSR is: " + csrSubject);
        // TODO: check if subject has the right subnet address

        try {
            Signature signature = Signature.getInstance(csr.getSignatureAlgorithm().getAlgorithm().getId(), "BC");
            signature.initVerify(controllerPublicKey);
            signature.update(csr.toASN1Structure().getCertificationRequestInfo().getEncoded());
            signature.verify(csr.getSignature());
        } catch (Exception e) {
            throw new SignatureException("Error verifying CSR signature: " + e.getMessage(), e);
        }

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
