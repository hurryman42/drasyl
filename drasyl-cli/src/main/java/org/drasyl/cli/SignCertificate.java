package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class SignCertificate {
    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String LINE_SEPARATOR = "\n";
    private static PKIXParameters PKIX_PARAMETERS;

    /**
     * Signs a CSR and therefore creates a new certificate.
     * With "me" in the commands and variable names I refer to the executing entity (a (sub-)controller or the CA)
     *
     * @param args a string array consisting of the file paths for the own private key, the own certificate, the CSR & the to be created certificate
     * @throws IOException thrown when something goes wrong with reading the files
     * @throws OperatorCreationException thrown when something went wrong with the certificate building
     * @throws CertificateException thrown when there are problems loading/reading a certificate
     */
    public static void main(String[] args) throws IOException, OperatorCreationException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());

        String myPrivateKeyFilePath = args[0];
        String certChainFilePath = args[1];
        String csrFilePath = args[2];
        String certFilePath = args[3];

        // load CSR file
        PEMParser pemParserCSR = new PEMParser(new FileReader(csrFilePath));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParserCSR.readObject();
        pemParserCSR.close();

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC"); // provider needed?

        // get public key out of the CSR
        SubjectPublicKeyInfo csrPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        PublicKey csrPublicKey = converter.getPublicKey(csrPublicKeyInfo);

        // get subject out of the CSR & check if it is right
        X500Name csrSubject = csr.getSubject();
        System.out.println("Subject of the CSR is: " + csrSubject);
        String csrSubjectString = csrSubject.toString();
        int startIndex = csrSubjectString.indexOf("CN=");
        if (startIndex != -1) {
            startIndex += 3;
            int endIndex = csrSubjectString.indexOf(",", startIndex);
            if (endIndex == -1) {
                endIndex = csrSubjectString.length();
            }
            String subnetAddress = csrSubjectString.substring(startIndex, endIndex).trim();
            System.out.println(subnetAddress);
            if (!subnetAddress.equals("10.1.0.0/24")) {
                throw new CertificateException("Wrong subnet address in CSR!");
            }
        }

        // load private key out of file
        PEMParser pemParserPrivateKey = new PEMParser(new FileReader(myPrivateKeyFilePath));
        PrivateKeyInfo myPrivateKeyInfo = (PrivateKeyInfo) pemParserPrivateKey.readObject();
        pemParserPrivateKey.close();
        PrivateKey myPrivateKey = converter.getPrivateKey(myPrivateKeyInfo);
        System.out.println(myPrivateKey);

        // load my certificate out of the certificate chain and then also the entire chain into the list of certificates
        //FileInputStream inputStream = new FileInputStream(certChainFilePath);
        //CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        //X509Certificate myCert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        List<X509Certificate> certificates = new ArrayList<>();
        PEMParser pemParserCerts = new PEMParser(new FileReader(certChainFilePath));
        X509CertificateHolder myCertHolder = (X509CertificateHolder) pemParserCerts.readObject();
        X509Certificate myCert = new JcaX509CertificateConverter().getCertificate(myCertHolder);
        certificates.add(myCert);
        System.out.println(myCert);
        Object object;
        while ((object = pemParserCerts.readObject()) != null) {
            if (object instanceof X509CertificateHolder) {
                X509Certificate cert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) object);
                certificates.add(cert);
            }
        }

        // load cacert as root certificate and add it as a trust anchor
        //String rootCertFilePath = "cacert.crt";
        //PEMParser pemParserRootCert = new PEMParser(new FileReader(rootCertFilePath));
        //X509Certificate rootCert = (X509Certificate) pemParserRootCert.readObject();
        //Set<TrustAnchor> trustAnchors = new HashSet<>();
        //trustAnchors.add(new TrustAnchor(rootCert, null));
        //PKIX_PARAMETERS = new PKIXParameters(trustAnchors);
        //PKIX_PARAMETERS.setRevocationEnabled(false);

        // create infos for the new X509 certificate
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

        // create certificate builder (subject taken from CSR)
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(myCert, serialNumber, notBefore, notAfter, csrSubject, csrPublicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(myPrivateKey);
        // build the certificate
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        //saveCertificateToFile(certificate, "signed.crt"); // just the signed certificate, not the rest of the chain
        certificates.add(certificate); // add the newly signed certificate to the chain
        saveCertificateChainToFile(certificates, certFilePath);
    }

    private static void saveCertificateToFile(X509Certificate certificate, String certFilePath) throws IOException {
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certFilePath));
        //JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
        pemWriter.writeObject(certificate);
        pemWriter.close();
    }

    private static void saveCertificateChainToFile(List<X509Certificate> certificates, String certFilePath) throws IOException {
        Collections.reverse(certificates);
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certFilePath));
        //JcaX509CertificateHolder certificateHolder = new JcaX509CertificateHolder(certificate);
        for (X509Certificate certificate : certificates) {
            pemWriter.writeObject(certificate);
        }
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
