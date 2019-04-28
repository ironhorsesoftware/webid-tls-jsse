package com.ironhorsesoftware.jsse.webid.tls;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilder;
import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilderFactory;

public class WebIdTrustManagerTest {

  private static final String SERVER_AUTH_TYPE = "RSA";
  private static final char[] KEYSTORE_PASSWORD = "password".toCharArray();
  private static final String WEBID_URI = "http://localhost:8282/mikepigott#i";

  private static WebIdX509CertificateBuilderFactory factory;
  private static KeyPairGenerator keyGen;

  private WebIdX509CertificateBuilder builder;
  private TrustManagerFactory tmFactory;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    final SecureRandom rng = new SecureRandom();

    keyGen =
        KeyPairGenerator.getInstance(
            "RSA",
            BouncyCastleProvider.PROVIDER_NAME);

    keyGen.initialize(2048, rng);

    final KeyPair keyPair = keyGen.generateKeyPair();

    factory =
        new WebIdX509CertificateBuilderFactory(keyPair);
  }

  @Before
  public void setUp() throws Exception {
    builder = factory.newCertificateBuilder();
    tmFactory = new TrustManagerFactory();
  }

  @Test
  public void testGetAcceptedIssuers() {
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    final X509Certificate[] trustedCertificates = trustManager.getAcceptedIssuers();
    assertNotNull(trustedCertificates);
    assertEquals(0, trustedCertificates.length);
  }

  @Test(expected = CertificateException.class)
  public void testCheckServerTrustedX509CertificateArrayString() throws CertificateException {
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    trustManager.checkServerTrusted(new X509Certificate[] { factory.getWebIdRootCertificate() }, SERVER_AUTH_TYPE);
  }

  @Test(expected = CertificateException.class)
  public void testCheckServerTrustedX509CertificateArrayStringSocket() throws CertificateException {
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    trustManager.checkServerTrusted(new X509Certificate[] { factory.getWebIdRootCertificate() }, SERVER_AUTH_TYPE, (Socket) null);
  }

  @Test(expected = CertificateException.class)
  public void testCheckServerTrustedX509CertificateArrayStringSSLEngine() throws CertificateException {
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    trustManager.checkServerTrusted(new X509Certificate[] { factory.getWebIdRootCertificate() }, SERVER_AUTH_TYPE, (SSLEngine) null);
  }

  @Test
  public void testVerifyCertificateAlreadyInKeyStore() throws CertificateException, OperatorCreationException, URISyntaxException, KeyStoreException, NoSuchAlgorithmException, IOException {
    final KeyPair keyPair = keyGen.generateKeyPair();
    final X509Certificate webIdCert = buildCertificate((RSAPublicKey) keyPair.getPublic());

    final X509Certificate[] certificateChain = new X509Certificate[]{ webIdCert, factory.getWebIdRootCertificate() };

    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, KEYSTORE_PASSWORD);
    keyStore.setKeyEntry(WEBID_URI, keyPair.getPrivate(), KEYSTORE_PASSWORD, certificateChain);

    tmFactory.engineInit(keyStore);

    final TrustManager[] trustManagers = tmFactory.engineGetTrustManagers();

    assertNotNull(trustManagers);
    assertEquals(1, trustManagers.length);
    assertTrue(trustManagers[0] instanceof WebIdTrustManager);

    final WebIdTrustManager trustManager = (WebIdTrustManager) trustManagers[0];

    trustManager.checkClientTrusted(certificateChain, "RSA");
  }

  private X509Certificate buildCertificate(RSAPublicKey publicKey) throws URISyntaxException, CertIOException, CertificateException, OperatorCreationException {
    final int yearsValid = 1;

    builder.setCommonName("Michael Pigott");
    builder.setPublicKey(publicKey);
    builder.addWebId(new URI(WEBID_URI));
    builder.setYearsValid(yearsValid);

    return builder.build();
  }
}
