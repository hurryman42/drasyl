/*
 * Copyright (c) 2024 Finn Eilmann
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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class TestingCertificateStuff {
    public static void main(String[] args) throws Exception {
        try {
            // get X509Certificate instance out of .crt-file for both the controller- and the CA-certificate
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            //final FileInputStream inputStream0 = new FileInputStream("controllerCertificate.crt");
            //final X509Certificate controllerCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream0);
            //System.out.println(convertCertToPem(controllerCertificate));

            final FileInputStream inputStream1 = new FileInputStream("cacert.crt");
            final X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream1);
            //System.out.println(caCertificate);
            //System.out.println(convertCertToPem(caCertificate));
            //System.out.println("----------------------------------------");
            // testing the verify function
            final PublicKey caPubKey = caCertificate.getPublicKey();
            caCertificate.verify(caPubKey);

            // check if certificate is expired
            caCertificate.checkValidity(new Date());

            // verify controller certificate with the public key of the CA certificate
            //controllerCertificate.verify(caCertificate.getPublicKey());
            //System.out.println("Certificate is valid.");

            final String rootCertFilePath = "cacert.crt";
            final String rootCertString = Files.readString(Path.of(rootCertFilePath));
            //System.out.println(rootCertString);

            final List<String> certificates = new ArrayList<>();
            final String certsString = Files.readString(Path.of("chain.crt"));
            final String[] certs = certsString.split("-----END CERTIFICATE-----");
            for (int i = 0; i < (certs.length - 1); i++) {
                String cert = certs[i] + "-----END CERTIFICATE-----\n";
                if (cert.startsWith("\n")) {
                    cert = cert.substring(1);
                }
                certificates.add(cert);
            }
            System.out.println(certificates);

            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (int i = 0; i < certificates.size() - 1; i++) {
                // load current certificate
                final String certificateString = certificates.get(i);
                final X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes()));
                //System.out.println(certificate);
                //System.out.println("----------------------------------------");

                // load next certificate (one up the chain)
                final String nextCertString = certificates.get(i + 1);
                final X509Certificate nextCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(nextCertString.getBytes()));
                //System.out.println(nextCert);
                //System.out.println("----------------------------------------");

                // check expiration dates
                certificate.checkValidity(new Date());
                nextCert.checkValidity(new Date());

                // verify current certificate with the public key of the next certificate
                final PublicKey pubKey = nextCert.getPublicKey();
                //System.out.println(pubKey);
                certificate.verify(pubKey);
                System.out.println("Certificate is valid.");
            }

            /*
            // load the trust store (e.g., the trusted CA certificates)
            KeyStore trustStore = KeyStore.getInstance("JKS"); // Java Key Store
            trustStore.load(new FileInputStream("TrustStore.jks"), "truststorePassword".toCharArray());

            // create a certificate chain including only the certificate to be verified
            CertPath certPath = certificateFactory.generateCertPath(List.of(controllerCertificate));

            // extract trust anchors from the trust store
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (Enumeration<String> aliases = trustStore.aliases(); aliases.hasMoreElements();) {
                Certificate trustedCert = trustStore.getCertificate(aliases.nextElement());
                controllerCertificate.verify(trustedCert.getPublicKey());
                if (trustedCert instanceof X509Certificate) {
                    trustAnchors.add(new TrustAnchor((X509Certificate) trustedCert, null));
                }
            }

            // set up the PKIX parameters with the trust anchors
            PKIXParameters PKIXParams = new PKIXParameters(trustAnchors);
            PKIXParams.setRevocationEnabled(false);  // disable CRL checking for simplicity

            // create the CertPathValidator & validate the path
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            certPathValidator.validate(certPath, PKIXParams);
            */
        }
        catch (Exception e) {
            System.out.println("Error processing certificate: " + e.getMessage());
        }
    }

    public static String convertCertToPem(final X509Certificate certificate) throws CertificateEncodingException, IOException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8));
        final byte[] cert = certificate.getEncoded();
        return "-----END CERTIFICATE-----" + "\n" + encoder.encodeToString(cert) + "\n" + "-----END PRIVATE KEY-----";
    }
}
