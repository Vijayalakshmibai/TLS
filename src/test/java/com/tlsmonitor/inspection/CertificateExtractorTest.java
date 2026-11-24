package com.tlsmonitor.inspection;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.tls.CertificateExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertificateExtractorTest {

    @Mock
    private X509Certificate mockCert;

    @Mock
    private RSAPublicKey mockRsaKey;

    private CertificateExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new CertificateExtractor();
    }

    @Test
    void testExtractDetailsFromValidCertificate() throws Exception {
        X500Principal subject = new X500Principal("CN=example.com,O=Example Corp,C=US");
        X500Principal issuer = new X500Principal("CN=DigiCert Global Root CA,O=DigiCert Inc,C=US");
        Date notBefore = Date.from(Instant.now().minus(30, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(60, ChronoUnit.DAYS));

        when(mockCert.getSubjectX500Principal()).thenReturn(subject);
        when(mockCert.getIssuerX500Principal()).thenReturn(issuer);
        when(mockCert.getSerialNumber()).thenReturn(new BigInteger("123456789ABCDEF", 16));
        when(mockCert.getNotBefore()).thenReturn(notBefore);
        when(mockCert.getNotAfter()).thenReturn(notAfter);
        when(mockCert.getSigAlgName()).thenReturn("SHA256withRSA");
        when(mockCert.getPublicKey()).thenReturn(mockRsaKey);
        when(mockRsaKey.getAlgorithm()).thenReturn("RSA");
        when(mockRsaKey.getModulus()).thenReturn(BigInteger.ONE.shiftLeft(2047));
        when(mockCert.getEncoded()).thenReturn(new byte[]{0x01, 0x02, 0x03, 0x04});

        CertificateDetails details = extractor.extractDetails(mockCert, 10L, 1L, 2);

        assertNotNull(details);
        assertEquals(10L, details.getScanId());
        assertEquals(1L, details.getWebsiteId());
        assertEquals(2, details.getChainLength());
        assertEquals("CN=example.com,O=Example Corp,C=US", details.getSubject());
        assertEquals("CN=DigiCert Global Root CA,O=DigiCert Inc,C=US", details.getIssuer());
        assertEquals("123456789ABCDEF", details.getSerialNumber());
        assertEquals("SHA256withRSA", details.getSignatureAlgorithm());
        assertEquals("RSA", details.getPublicKeyAlgorithm());
        assertEquals(2048, details.getKeySize());
        assertFalse(details.isExpired());
        assertFalse(details.isNotYetValid());
        assertTrue(details.getDaysRemaining() > 0);
        assertFalse(details.isSelfSigned());
        assertNotNull(details.getSha256Fingerprint());
    }

    @Test
    void testExtractDetailsFromNotYetValidCertificate() throws Exception {
        X500Principal subject = new X500Principal("CN=future.example.com");
        X500Principal issuer = new X500Principal("CN=DigiCert Global Root CA");
        Date notBefore = Date.from(Instant.now().plus(10, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        when(mockCert.getSubjectX500Principal()).thenReturn(subject);
        when(mockCert.getIssuerX500Principal()).thenReturn(issuer);
        when(mockCert.getSerialNumber()).thenReturn(BigInteger.TEN);
        when(mockCert.getNotBefore()).thenReturn(notBefore);
        when(mockCert.getNotAfter()).thenReturn(notAfter);
        when(mockCert.getSigAlgName()).thenReturn("SHA256withRSA");
        when(mockCert.getPublicKey()).thenReturn(mockRsaKey);
        when(mockRsaKey.getAlgorithm()).thenReturn("RSA");
        when(mockRsaKey.getModulus()).thenReturn(BigInteger.ONE.shiftLeft(2047));
        when(mockCert.getEncoded()).thenReturn(new byte[]{0x01, 0x02});

        CertificateDetails details = extractor.extractDetails(mockCert, 20L, 2L, 1);

        assertNotNull(details);
        assertTrue(details.isNotYetValid());
        assertFalse(details.isExpired());
    }

    @Test
    void testDetectSelfSignedCertificate() throws Exception {
        X500Principal selfPrincipal = new X500Principal("CN=SelfSignedHost");
        when(mockCert.getSubjectX500Principal()).thenReturn(selfPrincipal);
        when(mockCert.getIssuerX500Principal()).thenReturn(selfPrincipal);
        when(mockCert.getPublicKey()).thenReturn(mockRsaKey);
        doNothing().when(mockCert).verify(mockRsaKey);

        assertTrue(extractor.isSelfSigned(mockCert));
    }
}
