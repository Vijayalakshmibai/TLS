package com.tlsmonitor.testutil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class CertificateTestUtils {

    public static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static X509Certificate generateCaCertificate(KeyPair keyPair, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now().minus(365, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(3650, ChronoUnit.DAYS));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, keyPair.getPublic()
        );
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate generateSignedCertificate(
            String subjectDn,
            KeyPair subjectKeyPair,
            X500Name issuerName,
            PrivateKey issuerPrivateKey,
            Date notBefore,
            Date notAfter,
            List<String> dnsSans,
            List<String> ipSans
    ) throws Exception {
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + Math.abs(new SecureRandom().nextLong() % 10000000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName, serial, notBefore, notAfter, subject, subjectKeyPair.getPublic()
        );

        List<GeneralName> generalNamesList = new ArrayList<>();
        if (dnsSans != null) {
            for (String dns : dnsSans) {
                generalNamesList.add(new GeneralName(GeneralName.dNSName, dns));
            }
        }
        if (ipSans != null) {
            for (String ip : ipSans) {
                try {
                    byte[] ipBytes = java.net.InetAddress.getByName(ip).getAddress();
                    generalNamesList.add(new GeneralName(GeneralName.iPAddress, new org.bouncycastle.asn1.DEROctetString(ipBytes)));
                } catch (Exception e) {
                    generalNamesList.add(new GeneralName(GeneralName.iPAddress, ip));
                }
            }
        }

        if (!generalNamesList.isEmpty()) {
            GeneralNames generalNames = new GeneralNames(generalNamesList.toArray(new GeneralName[0]));
            certBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    public static X509Certificate generateSignedCertificate(
            String subjectDn,
            KeyPair subjectKeyPair,
            X509Certificate caCert,
            PrivateKey issuerPrivateKey,
            Date notBefore,
            Date notAfter,
            List<String> dnsSans,
            List<String> ipSans
    ) throws Exception {
        X500Name issuerName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        return generateSignedCertificate(
                subjectDn, subjectKeyPair, issuerName, issuerPrivateKey, notBefore, notAfter, dnsSans, ipSans
        );
    }

    public static X509Certificate generateSelfSignedCertificate(
            String dn,
            KeyPair keyPair,
            Date notBefore,
            Date notAfter,
            List<String> dnsSans
    ) throws Exception {
        X500Name name = new X500Name(dn);
        return generateSignedCertificate(
                dn, keyPair, name, keyPair.getPrivate(), notBefore, notAfter, dnsSans, null
        );
    }

    public static KeyStore createKeyStore(PrivateKey privateKey, Certificate[] certChain, String alias, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password);
        keyStore.setKeyEntry(alias, privateKey, password, certChain);
        return keyStore;
    }

    public static KeyStore createTrustStore(X509Certificate caCert, String alias) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry(alias, caCert);
        return trustStore;
    }

    public static SSLContext createServerSslContext(KeyStore keyStore, char[] password) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }

    public static SSLContext createClientTrustSslContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }
}
