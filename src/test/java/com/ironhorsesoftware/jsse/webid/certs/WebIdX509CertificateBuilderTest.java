/* Copyright 2019 Iron Horse Software, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ironhorsesoftware.jsse.webid.certs;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.Constants;

/**
 * Tests {@link WebIdX509CertificateBuilderFactory}.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class WebIdX509CertificateBuilderTest {

  private static SecureRandom rng;
  private static KeyPairGenerator keyGen;

  private KeyPair keyPair;

  /**
   * Adds the {@link BouncyCastleProvider} to the
   * security provider list, and initializes the
   * random number generator.
   * 
   * @throws java.lang.Exception If unable to configure the key generator.
   */
  @BeforeClass
  public static void beforeClass() throws Exception {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    rng = new SecureRandom();

    keyGen =
        KeyPairGenerator.getInstance(
            "RSA",
            BouncyCastleProvider.PROVIDER_NAME);

    keyGen.initialize(2048, rng);
  }

  /**
   * Sets up the public-key/secret-key pair to be used in the test.
   */
  @Before
  public void setUp() {
    this.keyPair = keyGen.generateKeyPair();
  }

  @Test
  public void testKeyPairConstructor() throws Exception {
    final WebIdX509CertificateBuilderFactory factory =
        new WebIdX509CertificateBuilderFactory(this.keyPair);

    assertEquals(this.keyPair.getPrivate(), factory.getWebIdRootPrivateKey());

    final X509Certificate certificate = factory.getWebIdRootCertificate();

    assertNotNull(certificate);
    assertEquals(this.keyPair.getPublic(), certificate.getPublicKey());
    assertEquals(Constants.WEBID_ISSUER, certificate.getSubjectX500Principal());
    assertEquals(Constants.WEBID_ISSUER, certificate.getSubjectX500Principal());
  }

  @Test
  public void testTwoKeyConstructor() throws Exception {
    final WebIdX509CertificateBuilderFactory factory =
        new WebIdX509CertificateBuilderFactory(this.keyPair.getPublic(), this.keyPair.getPrivate());

    assertEquals(this.keyPair.getPrivate(), factory.getWebIdRootPrivateKey());

    final X509Certificate certificate = factory.getWebIdRootCertificate();

    assertNotNull(certificate);
    assertEquals(this.keyPair.getPublic(), certificate.getPublicKey());
    assertEquals(Constants.WEBID_ISSUER, certificate.getSubjectX500Principal());
    assertEquals(Constants.WEBID_ISSUER, certificate.getSubjectX500Principal());
  }

  @Test
  public void testCertificateConstructor() throws Exception {
    final WebIdX509CertificateBuilderFactory firstFactory =
        new WebIdX509CertificateBuilderFactory(this.keyPair.getPublic(), this.keyPair.getPrivate());

    final WebIdX509CertificateBuilderFactory factory =
        new WebIdX509CertificateBuilderFactory(firstFactory.getWebIdRootCertificate(), firstFactory.getWebIdRootPrivateKey());

    assertEquals(this.keyPair.getPrivate(), factory.getWebIdRootPrivateKey());
    assertEquals(firstFactory.getWebIdRootCertificate(), factory.getWebIdRootCertificate());
  }

  @Test
  public void testKeyStoreConstructor() throws Exception {
    final WebIdX509CertificateBuilderFactory firstFactory =
        new WebIdX509CertificateBuilderFactory(this.keyPair.getPublic(), this.keyPair.getPrivate());


    final String alias = "WebID";
    final char[] password = "password".toCharArray();
    final X509Certificate certificate = firstFactory.getWebIdRootCertificate();

    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, password);
    keyStore.setKeyEntry(alias, firstFactory.getWebIdRootPrivateKey(), password, new X509Certificate[] { certificate });

    final WebIdX509CertificateBuilderFactory factory =
        new WebIdX509CertificateBuilderFactory(keyStore, alias, password);

    assertEquals(this.keyPair.getPrivate(), factory.getWebIdRootPrivateKey());
    assertEquals(certificate, factory.getWebIdRootCertificate());
  }
}
