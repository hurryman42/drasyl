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
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            //FileInputStream inputStream0 = new FileInputStream("controllerCertificate.crt");
            //X509Certificate controllerCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream0);
            //System.out.println(convertCertToPem(controllerCertificate));

            FileInputStream inputStream1 = new FileInputStream("cacert.crt");
            X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream1);
            //System.out.println(caCertificate);
            //System.out.println(convertCertToPem(caCertificate));
            //System.out.println("----------------------------------------");
            // testing the verify function
            PublicKey caPubKey = caCertificate.getPublicKey();
            caCertificate.verify(caPubKey);

            // check if certificate is expired
            caCertificate.checkValidity(new Date());

            // verify controller certificate with the public key of the CA certificate
            //controllerCertificate.verify(caCertificate.getPublicKey());
            //System.out.println("Certificate is valid.");

            String rootCertFilePath = "cacert.crt";
            String rootCertString = Files.readString(Path.of(rootCertFilePath));
            //System.out.println(rootCertString);

            List<String> certificates = new ArrayList<>();
            String certsString = Files.readString(Path.of("chain.crt"));
            String[] certs = certsString.split("-----END CERTIFICATE-----");
            for (int i=0; i<(certs.length-1); i++) {
                String cert = certs[i] + "-----END CERTIFICATE-----\n";
                if (cert.startsWith("\n")) {
                    cert = cert.substring(1);
                }
                certificates.add(cert);
            }
            System.out.println(certificates);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (int i=0; i<certificates.size()-1; i++) {
                // load current certificate
                String certificateString = certificates.get(i);
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes()));
                //System.out.println(certificate);
                //System.out.println("----------------------------------------");

                // load next certificate (one up the chain)
                String nextCertString = certificates.get(i+1);
                X509Certificate nextCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(nextCertString.getBytes()));
                //System.out.println(nextCert);
                //System.out.println("----------------------------------------");

                // check expiration dates
                certificate.checkValidity(new Date());
                nextCert.checkValidity(new Date());

                // verify current certificate with the public key of the next certificate
                PublicKey PubKey = nextCert.getPublicKey();
                //System.out.println(PubKey);
                certificate.verify(PubKey);
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
