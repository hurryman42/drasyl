package org.drasyl.cli;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ValidateX509Certificate {
    public static void main(String[] args) throws Exception {
        try {
            // get X509Certificate instance out of .pem-file
            FileInputStream inputStream = new FileInputStream("certificate.pem");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            //System.out.println(certificate); // DEBUG

            // check if certificate is expired
            certificate.checkValidity(new Date());

            // load the trust store (e.g., the trusted CA certificates)
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("TrustStore.jks"), "truststorePassword".toCharArray());

            // create a certificate chain including only the certificate to be verified
            CertPath certPath = certificateFactory.generateCertPath(List.of(certificate));

            // extract trust anchors from the trust store
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (Enumeration<String> aliases = trustStore.aliases(); aliases.hasMoreElements();) {
                Certificate trustedCert = trustStore.getCertificate(aliases.nextElement());
                certificate.verify(trustedCert.getPublicKey());
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

            System.out.println("Certificate is valid.");
        }
        catch (CertPathValidatorException e) {
            System.out.println("Certificate path could not be validated: " + e.getMessage());
        }
        catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            System.out.println("Error processing certificate: " + e.getMessage());
        }
    }
}
