package org.drasyl.cli;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CheckX509Certificate {
    public static void main(String[] args) throws Exception {
        try {
            // get X509Certificate instance out of .crt-file for both the controller- and the CA-certificate
            FileInputStream inputStream0 = new FileInputStream("controllerCertificate.crt");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate controllerCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream0);
            //System.out.println(controllerCertificate); // DEBUG
            FileInputStream inputStream1 = new FileInputStream("cacert.crt");
            X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream1);
            //System.out.println(caCertificate); // DEBUG

            // check if certificates are expired
            controllerCertificate.checkValidity(new Date());
            caCertificate.checkValidity(new Date());

            // verify controller certificate with the public key of the CA certificate
            controllerCertificate.verify(caCertificate.getPublicKey());
            System.out.println("Certificate is valid.");

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
        catch (CertificateException | IOException | NoSuchAlgorithmException e) {
            System.out.println("Error processing certificate: " + e.getMessage());
        }
    }
}
