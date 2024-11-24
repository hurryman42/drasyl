package org.drasyl.cli;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

public class CreateCSR {
    public static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_KEY = "-----END PRIVATE KEY-----";
    public static final String BEGIN_CSR = "-----BEGIN SIGNING REQUEST-----";
    public static final String END_CSR = "-----END SIGNING REQUEST-----";
    public static final String LINE_SEPARATOR = "\n";

    /**
     * given an ed25519 keypair and a subnet address it creates a CSR for that subnet
     * and saves it in PEM format under the given FilePath
     *
     * @param String publicKeyFilePath
     * @param String privateKeyFilePath
     * @param String subnet
     * @param String CSRFilePath
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static void main(String[] args) throws IOException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        // load keys
        String publicKeyFilePath = args[0];
        String privateKeyFilePath = args[1];
        PublicKey publicKey = loadPublicKey(publicKeyFilePath);
        PrivateKey privateKey = loadPrivateKey(privateKeyFilePath);

        // create only subject info for future certificate
        String subnet = args[2];
        X500Name subjectName = new X500Name(createSubjectString(subnet));

        // create CSR builder
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectName, publicKey);
        // create a content signer
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the CSR
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        //convertCSRToPemString(csr);
        writeCSRToFile(csr, args[3]);
        System.out.println("CSR successfully saved as " + args[3]);
    }

    private static PrivateKey loadPrivateKey(String privateKeyFilePath) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(privateKeyFilePath));
        PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
        pemParser.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPrivateKey(keyInfo);
    }

    private static PublicKey loadPublicKey(String publicKeyFilePath) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(publicKeyFilePath));
        SubjectPublicKeyInfo keyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
        pemParser.close();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPublicKey(keyInfo);
    }

    private static String createSubjectString(String subnet) {
        String subjectOrganizationName = "subjectO"; //TODO: change to right organization name
        String subjectOrganizationUnitName = "subjectOU"; //TODO: change to right organization unit name
        String subjectCountry = "DE"; //TODO: change to right country code
        String subjectState = "subjectST"; //TODO: change to right state code
        String subjectLocation = "subjectL"; //TODO: change to right location
        return "CN=" + subnet + ", O=" + subjectOrganizationName + ", OU=" + subjectOrganizationUnitName + ", C=" + subjectCountry + ", ST=" + subjectState + ", L=" + subjectLocation;
    }

    private static void writeCSRToFile(PKCS10CertificationRequest csr, String FilePath) throws IOException {
        JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(FilePath));
        pemWriter.writeObject(csr);
        pemWriter.close();
    }

    private static String convertCSRToPemString(final PKCS10CertificationRequest csr) throws CertificateEncodingException, IOException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        byte[] csrBytes = csr.getEncoded();

        return BEGIN_CSR + LINE_SEPARATOR + encoder.encodeToString(csrBytes) + LINE_SEPARATOR + END_CSR;
    }
}
