package com.ironhorsesoftware.jsse.webid.tls;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;

import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.Constants;

public class TrustManagerFactoryTest extends WebIdTrustManagerFactory {

  private void testInvariants() {
    final TrustManager[] trustManagers = super.engineGetTrustManagers();

    assertNotNull(trustManagers);
    assertEquals(1, trustManagers.length);
    assertTrue(trustManagers[0] instanceof WebIdTrustManager);

    final X509Certificate[] acceptedIssuers = ((WebIdTrustManager) trustManagers[0]).getAcceptedIssuers();

    assertNotNull(acceptedIssuers);
    assertEquals(1, acceptedIssuers.length);

    assertEquals(Constants.WEBID_ISSUER, acceptedIssuers[0].getSubjectX500Principal());
    assertEquals(Constants.WEBID_ISSUER, acceptedIssuers[0].getSubjectDN());

    assertEquals(Constants.WEBID_ISSUER, acceptedIssuers[0].getIssuerX500Principal());
    assertEquals(Constants.WEBID_ISSUER, acceptedIssuers[0].getIssuerDN());
  }

  public void testWithoutInit() {
    testInvariants();
  }

  @Test
  public void testInitWithKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, "password".toCharArray());
    super.engineInit(keyStore);

    testInvariants();
  }

  @Test (expected = InvalidAlgorithmParameterException.class)
  public void testInitWithManagerFactoryParameters() throws InvalidAlgorithmParameterException {
    super.engineInit((ManagerFactoryParameters) null);
  }
}
