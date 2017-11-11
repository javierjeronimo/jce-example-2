package com.minsait.cybersec.learning.cryptojava.exercise2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Exercise2 {

    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week

    private final String provider;
    private final KeyPairGenerator kpGen;
    private final String signatureAlgorithm;
    private final JcaContentSignerBuilder contentSignerBuilder;
    private final JcaX509CertificateConverter certificateConverter;
    private final JcaX509CRLConverter crlConverter;
    private final DigestCalculator digestCalculator;

    /**
     * @param keySize            2048
     * @param provider           BC
     * @param keyAlgorithm       RSA
     * @param signatureAlgorithm SHA256WITHRSAENCRYPTION
     * @param digestAlgorithm    SHA256
     */
    public Exercise2(final String provider, final String keyAlgorithm, Integer keySize, final String signatureAlgorithm, final String digestAlgorithm) throws Exception {
        this.provider = provider;

        this.kpGen = KeyPairGenerator.getInstance(keyAlgorithm, this.provider);
        this.kpGen.initialize(keySize, new SecureRandom());

        this.signatureAlgorithm = signatureAlgorithm;
        this.contentSignerBuilder = new JcaContentSignerBuilder(this.signatureAlgorithm);

        if ("SHA1".equals(digestAlgorithm)) {
            this.digestCalculator = new MyDigestCalculator(MessageDigest.getInstance(digestAlgorithm), "1.3.14.3.2.26");

        } else if ("SHA256".equals(digestAlgorithm)) {
            this.digestCalculator = new MyDigestCalculator(MessageDigest.getInstance(digestAlgorithm), "2.16.840.1.101.3.4.2.1");

        } else {
            throw new IllegalArgumentException("Invalid digestAlgorithm. Shall be one of: [\"SHA1\", \"SHA256\"]");
        }

        this.certificateConverter = new JcaX509CertificateConverter();
        this.crlConverter = new JcaX509CRLConverter();
    }

    public KeyStore createKeyStore() throws Exception {
        KeyStore result = KeyStore.getInstance("JKS");
        result.load(null, null);
        return result;
    }

    public void saveKeyStore(KeyStore keyStore) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        keyStore.store(new FileOutputStream("mykeystore.jks"), "mypassword".toCharArray());
    }

    public KeyPair createKeyPair() {
        return this.kpGen.generateKeyPair();
    }

    public X509Certificate createV1Certificate(KeyPair keyPair) throws Exception {
        X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(
                new X500Principal("CN=Test CA Certificate v1"),    // issuer
                BigInteger.ONE,  // serial
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Principal("CN=Test CA Certificate v1"),    // subject
                keyPair.getPublic());

        return this.certificateConverter.getCertificate(
                certGen.build(contentSignerBuilder.build(keyPair.getPrivate()))
        );
    }

    public X509Certificate createV3Certificate(KeyPair keyPair) throws Exception {
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=Test CA Certificate v3"),    // issuer
                BigInteger.ONE.add(BigInteger.valueOf(2)),  // serial
                new Date(System.currentTimeMillis()),
                new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
                new X500Principal("CN=Test CA Certificate v3"),    // subject
                keyPair.getPublic());

        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certGen.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "testv3@test.test")));

        return this.certificateConverter.getCertificate(
                certGen.build(contentSignerBuilder.build(keyPair.getPrivate()))
        );
    }

    public X509CRL createX509CRL(X509Certificate certificate, PrivateKey key, BigInteger revokedSerial) throws Exception {

        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(certificate, new Date(System.currentTimeMillis()));

        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 100000));
        crlBuilder.addCRLEntry(revokedSerial, new Date(System.currentTimeMillis()), CRLReason.privilegeWithdrawn);

        crlBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                new JcaX509ExtensionUtils(this.digestCalculator).createAuthorityKeyIdentifier(certificate));

        crlBuilder.addExtension(
                Extension.cRLNumber,
                false,
                new CRLNumber(BigInteger.valueOf(1)));

        return this.crlConverter.getCRL(
                crlBuilder.build(this.contentSignerBuilder.build(key))
        );
    }

    private static class MyDigestCalculator
            implements DigestCalculator {

        private final String oid;
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        private MessageDigest digest;

        public MyDigestCalculator(MessageDigest digest, final String oid) {
            this.digest = digest;
            this.oid = oid;
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(this.oid));
        }

        public OutputStream getOutputStream() {
            return bOut;
        }

        public byte[] getDigest() {
            byte[] bytes = digest.digest(bOut.toByteArray());
            bOut.reset();
            return bytes;
        }
    }
}
