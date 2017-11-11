package com.minsait.cybersec.learning.cryptojava.exercise2;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@RunWith(JUnitPlatform.class)
class Exercise2Test {

    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

    public static Stream<Arguments> paramsProvider() {
        return Stream.of(
                Arguments.of("BC", "RSA", 1024, "SHA1WITHRSAENCRYPTION", "SHA1"),
                Arguments.of("BC", "RSA", 2048, "SHA1WITHRSAENCRYPTION", "SHA1"),
                Arguments.of("BC", "RSA", 4096, "SHA1WITHRSAENCRYPTION", "SHA1"),

                Arguments.of("BC", "RSA", 1024, "SHA256WITHRSAENCRYPTION", "SHA256"),
                Arguments.of("BC", "RSA", 2048, "SHA256WITHRSAENCRYPTION", "SHA256"),
                Arguments.of("BC", "RSA", 4096, "SHA256WITHRSAENCRYPTION", "SHA256")
        );
    }

    @BeforeAll
    static void mainSetUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    public void testCreateKeyStore(final String provider, final String keyAlgorithm, final Integer keySize, final String signatureAlgorithm, final String digestAlgorithm) throws Exception {
        Exercise2 testObject = new Exercise2(provider, keyAlgorithm, keySize, signatureAlgorithm, digestAlgorithm);


        KeyStore ks = testObject.createKeyStore();

        assertEquals(ks.size(), 0);
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    public void testCreateV1Certificate(final String provider, final String keyAlgorithm, final Integer keySize, final String signatureAlgorithm, final String digestAlgorithm) throws Exception {
        Exercise2 testObject = new Exercise2(provider, keyAlgorithm, keySize, signatureAlgorithm, digestAlgorithm);


        KeyPair kp = testObject.createKeyPair();
        X509Certificate cert = testObject.createV1Certificate(kp);

        cert.verify(kp.getPublic());
        assertEquals("CN=Test CA Certificate v1", cert.getIssuerDN().getName());
        assertTrue(cert.getNotBefore().getTime() <= System.currentTimeMillis());
        assertTrue(cert.getNotAfter().getTime() <= System.currentTimeMillis() + VALIDITY_PERIOD);
        assertEquals("CN=Test CA Certificate v1", cert.getSubjectDN().getName());
        assertEquals(BigInteger.ONE, cert.getSerialNumber());
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    public void testCreateV3Certificate(final String provider, final String keyAlgorithm, final Integer keySize, final String signatureAlgorithm, final String digestAlgorithm) throws Exception {
        Exercise2 testObject = new Exercise2(provider, keyAlgorithm, keySize, signatureAlgorithm, digestAlgorithm);


        KeyPair kp = testObject.createKeyPair();
        X509Certificate cert = testObject.createV3Certificate(kp);

        cert.verify(kp.getPublic());
        assertEquals("CN=Test CA Certificate v3", cert.getIssuerDN().getName());
        assertTrue(cert.getNotBefore().getTime() <= System.currentTimeMillis());
        assertTrue(cert.getNotAfter().getTime() <= System.currentTimeMillis() + VALIDITY_PERIOD);
        assertEquals("CN=Test CA Certificate v3", cert.getSubjectDN().getName());
        assertEquals(BigInteger.ONE.add(BigInteger.valueOf(2)), cert.getSerialNumber());
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    public void testCreateCRL(final String provider, final String keyAlgorithm, final Integer keySize, final String signatureAlgorithm, final String digestAlgorithm) throws Exception {
        Exercise2 testObject = new Exercise2(provider, keyAlgorithm, keySize, signatureAlgorithm, digestAlgorithm);


        KeyPair kp = testObject.createKeyPair();
        X509Certificate cert = testObject.createV1Certificate(kp);
        BigInteger revokedSerial = BigInteger.valueOf(2);

        X509CRL crl = testObject.createX509CRL(cert, kp.getPrivate(), revokedSerial);

        crl.verify(kp.getPublic());
        assertEquals("CN=Test CA Certificate v1", crl.getIssuerDN().getName());
    }
}
