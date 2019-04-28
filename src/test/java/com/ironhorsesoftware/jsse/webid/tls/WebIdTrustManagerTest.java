package com.ironhorsesoftware.jsse.webid.tls;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.HttpURLConnection;
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

import org.apache.jena.riot.RDFLanguages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilder;
import com.ironhorsesoftware.jsse.webid.certs.WebIdX509CertificateBuilderFactory;

public class WebIdTrustManagerTest {

  private static final String SERVER_AUTH_TYPE = "RSA";

  private static WebIdX509CertificateBuilderFactory factory;
  private static KeyPairGenerator keyGen;

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
    final char[] keyStorePassword = "password".toCharArray();
    final String webIdUri = "http://www.ironhorsesoftware.com/mikepigott#map";
    final KeyPair keyPair = keyGen.generateKeyPair();

    final WebIdX509CertificateBuilder builder = factory.newCertificateBuilder();
    final TrustManagerFactory tmFactory = new TrustManagerFactory();

    builder.setCommonName("Michael Pigott");
    builder.setPublicKey((RSAPublicKey) keyPair.getPublic());
    builder.addWebId(new URI(webIdUri));
    builder.setYearsValid(1);

    final X509Certificate webIdCert = builder.build();

    final X509Certificate[] certificateChain = new X509Certificate[]{ webIdCert, factory.getWebIdRootCertificate() };

    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, keyStorePassword);
    keyStore.setKeyEntry(webIdUri, keyPair.getPrivate(), keyStorePassword, certificateChain);

    tmFactory.engineInit(keyStore);

    final TrustManager[] trustManagers = tmFactory.engineGetTrustManagers();

    assertNotNull(trustManagers);
    assertEquals(1, trustManagers.length);
    assertTrue(trustManagers[0] instanceof WebIdTrustManager);

    final WebIdTrustManager trustManager = (WebIdTrustManager) trustManagers[0];

    trustManager.checkClientTrusted(certificateChain, "RSA");
  }

  private void verifyHttpURLConnectionInvariants(HttpURLConnection conn) {
    assertTrue(conn.getInstanceFollowRedirects());

    final String acceptHeader = String.join(
        ",",
        RDFLanguages.TURTLE.getHeaderString(),
        RDFLanguages.RDFXML.getHeaderString(),
        RDFLanguages.NTRIPLES.getHeaderString(),
        RDFLanguages.JSONLD.getHeaderString());

    assertEquals(acceptHeader, conn.getRequestProperty("Accept"));
  }

  @Test
  public void testCreateWebIdProfileConnectionWithHashUri() throws CertificateException, URISyntaxException {
    final String webIdUri = "http://www.ironhorsesoftware.com/mikepigott#i";
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    final HttpURLConnection conn = trustManager.createWebIdProfileConnection(new URI(webIdUri));

    assertEquals(webIdUri.split("#")[0], conn.getURL().toExternalForm());

    verifyHttpURLConnectionInvariants(conn);
  }

  @Test
  public void testCreateWebIdProfileConnectionWithRedirectUri() throws CertificateException, URISyntaxException {
    final String webIdUri = "http://www.ironhorsesoftware.com/mikepigott";
    final WebIdTrustManager trustManager = new WebIdTrustManager();
    final HttpURLConnection conn = trustManager.createWebIdProfileConnection(new URI(webIdUri));

    assertEquals(webIdUri, conn.getURL().toExternalForm());

    verifyHttpURLConnectionInvariants(conn);
  }

  @Test
  public void testGetJenaRdfEncodingType() {
    final String[] inputMapping = new String[] {
        RDFLanguages.TURTLE.getHeaderString(),
        RDFLanguages.RDFXML.getHeaderString(),
        RDFLanguages.NTRIPLES.getHeaderString(),
        RDFLanguages.JSONLD.getHeaderString()
    };

    final String[] outputMapping = new String[] {
        RDFLanguages.TURTLE.getName(),
        RDFLanguages.RDFXML.getName(),
        RDFLanguages.NTRIPLES.getName(),
        RDFLanguages.JSONLD.getName()
    };

    assertEquals(inputMapping.length, outputMapping.length);

    for (int idx = 0; idx < inputMapping.length; ++idx) {
      assertEquals(outputMapping[idx], WebIdTrustManager.getJenaRdfEncodingType(inputMapping[idx]));
    }
  }

  @Test
  public void testValidateClaim() {
    // TODO: Build a model of the correct structure, the corresponding WebIdClaim, and verify they match.
  }
}
