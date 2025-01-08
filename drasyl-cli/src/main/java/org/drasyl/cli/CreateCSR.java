/*
 * Copyright (c) 2020-2024 Heiko Bornholdt and Kevin Röbert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
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
import java.util.Base64;

public class CreateCSR {
    public static final String BEGIN_CSR = "-----BEGIN SIGNING REQUEST-----";
    public static final String END_CSR = "-----END SIGNING REQUEST-----";
    public static final String LINE_SEPARATOR = "\n";

    /**
     * given an ed25519 keypair and a subnet address it creates a CSR for that subnet
     * and saves it in PEM format under the given FilePath
     *
     * @param args a string array consisting of the file paths for the public and private key as well as the subnet string and the name under which the CSR should be saved
     * @throws IOException thrown when something goes wrong with reading the files
     * @throws OperatorCreationException thrown when something went wrong with the certificate building
     */
    public static void main(String[] args) throws IOException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        final String publicKeyFilePath = args[0];
        final String privateKeyFilePath = args[1];
        final String subnet = args[2];
        final String csrFilePath = args[3];

        // load keys
        final PublicKey publicKey = loadPublicKey(publicKeyFilePath);
        final PrivateKey privateKey = loadPrivateKey(privateKeyFilePath);

        // create only subject info for future certificate
        final X500Name subjectName = new X500Name(createSubjectString(subnet));

        // create CSR builder
        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectName, publicKey);
        // create a content signer
        final ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the CSR
        final PKCS10CertificationRequest csr = csrBuilder.build(signer);

        //convertCSRToPemString(csr);
        writeCSRToFile(csr, csrFilePath);
        System.out.println("CSR successfully saved as " + csrFilePath);
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

    private static String createSubjectString(String subnet) {
        final String subjectOrganizationName = "subjectO"; //TODO: change to right organization name
        final String subjectOrganizationUnitName = "subjectOU"; //TODO: change to right organization unit name
        final String subjectCountry = "DE"; //TODO: change to right country code
        final String subjectState = "subjectST"; //TODO: change to right state code
        final String subjectLocation = "subjectL"; //TODO: change to right location
        return "CN=" + subnet + ", O=" + subjectOrganizationName + ", OU=" + subjectOrganizationUnitName + ", C=" + subjectCountry + ", ST=" + subjectState + ", L=" + subjectLocation;
    }

    private static void writeCSRToFile(PKCS10CertificationRequest csr, String filePath) throws IOException {
        final JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filePath));
        pemWriter.writeObject(csr);
        pemWriter.close();
    }

    private static String convertCSRToPemString(final PKCS10CertificationRequest csr) throws IOException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8));
        final byte[] csrBytes = csr.getEncoded();

        return BEGIN_CSR + LINE_SEPARATOR + encoder.encodeToString(csrBytes) + LINE_SEPARATOR + END_CSR;
    }
}
