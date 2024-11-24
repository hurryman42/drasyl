package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class SignCertificate {
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_KEY = "-----END PRIVATE KEY-----";
    public static final String LINE_SEPARATOR = "\n";
    private static PKIXParameters PKIX_PARAMETERS;

    public static void main(String[] args) throws IOException, OperatorCreationException, CertificateException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());

        String caPrivateKeyFilePath = args[0];
        String csrFilePath = args[1];
        String certFilePath = args[2];

        // load CSR file
        PEMParser pemParserCSR = new PEMParser(new FileReader(csrFilePath));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParserCSR.readObject();
        pemParserCSR.close();

        // get public key out of the CSR
        SubjectPublicKeyInfo controllerPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PublicKey controllerPublicKey = converter.getPublicKey(controllerPublicKeyInfo);

        // get subject out of the CSR
        X500Name csrSubject = csr.getSubject();
        System.out.println("Subject of the CSR is: " + csrSubject);

        // TODO: check if subject has the right subnet address

        // load CA's private key
        // TODO: do we have the CA's private key? what instead about the chaining of certificates back to the CA?
        PEMParser pemParserPrivateKey = new PEMParser(new FileReader(caPrivateKeyFilePath));
        Object pemObject = pemParserPrivateKey.readObject();
        PrivateKeyInfo caPrivateKeyInfo = null; // TODO: make this more beautiful
        if (pemObject instanceof PrivateKeyInfo) {
            caPrivateKeyInfo = (PrivateKeyInfo) pemObject;
        }
        pemParserPrivateKey.close();
        PrivateKey caPrivateKey = converter.getPrivateKey(caPrivateKeyInfo);
        System.out.println(caPrivateKey);

        // load cacert as root certificate and add it as a trust anchor TODO: necessary?
        String rootCertFilePath = "cacert.crt";
        PEMParser pemParserRootCert = new PEMParser(new FileReader(rootCertFilePath));
        final X509Certificate rootCert = (X509Certificate) pemParserRootCert.readObject();
        final Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(rootCert, null));
        PKIX_PARAMETERS = new PKIXParameters(trustAnchors);
        PKIX_PARAMETERS.setRevocationEnabled(false);

        // create infos for the new X509 certificate
        X500Name issuerName = new X500Name("CN=drasylController, O=drasyl, C=DE, ST=HH, L=Hamburg");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

        // create certificate builder (subject taken from CSR)
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, csrSubject, controllerPublicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(caPrivateKey);
        // build the certificate
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        saveCertificateToFile(certificate, certFilePath);
    }

    private static void saveCertificateToFile(X509Certificate certificate, String certFilePath) throws IOException, CertificateEncodingException {
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certFilePath));
        JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
        pemWriter.writeObject(certificateHolder);
        pemWriter.close();
    }

    private static String convertCertToPemString(final X509Certificate certificate) throws CertificateEncodingException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        byte[] cert = certificate.getEncoded();

        return BEGIN_CERT + LINE_SEPARATOR + encoder.encodeToString(cert) + LINE_SEPARATOR + END_CERT;
    }

    private boolean validateCertificateChain(final X509Certificate... certificates) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(List.of(certificates));
            CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());

            cpv.validate(certPath, PKIX_PARAMETERS);
            return true;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertPathValidatorException | CertificateException e) {
            return false;
        }
    }
}
