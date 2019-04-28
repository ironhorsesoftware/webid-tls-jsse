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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the {@link WebIdX509CertificateBuilder}.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class WebIdX509CertificateBuilderTest {

  private static WebIdX509CertificateBuilderFactory factory;
  private static KeyPairGenerator keyGen;

  private WebIdX509CertificateBuilder builder;

  /**
   * Configures a {@link WebIdX509CertificateBuilderFactory}
   * for use when running the tests.
   *
   * @throws java.lang.Exception If unable to construct the certificate builder factory.
   */
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

  /**
   * Configures a {@link WebIdX509CertificateBuilder}
   * for use when running each test.
   *
   * @throws java.lang.Exception If unable to construct the certificate builder.
   */
  @Before
  public void setUp() throws Exception {
    builder = factory.newCertificateBuilder();
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetNullCommonName() {
    builder.setCommonName(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetEmptyCommonName() {
    builder.setCommonName("   ");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetInvalidCommonName() {
    builder.setCommonName("<?+#*3>");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetNullRSAPublicKey() {
    builder.setPublicKey((RSAPublicKey) null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetNullSPKAC() throws InvalidKeyException, OperatorCreationException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
    builder.setPublicKey(null, null);
  }

  private JcaSignedPublicKeyAndChallenge buildSPKAC(String keyPairGenAlg, int keySize, String sigAlgOid, String challenge) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
    final AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(sigAlgOid));

    final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyPairGenAlg);
    keyGen.initialize(keySize);

    final KeyPair keyPair = keyGen.genKeyPair();

    final NetscapeCertRequest ncr = new NetscapeCertRequest(challenge, algId, keyPair.getPublic());
    ncr.sign(keyPair.getPrivate());
    ncr.verify(challenge);

    final JcaSignedPublicKeyAndChallenge spkac = new JcaSignedPublicKeyAndChallenge(ncr.toASN1Primitive().getEncoded());

    assertEquals(challenge, spkac.getChallenge());
    assertEquals(sigAlgOid, spkac.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId());
    assertEquals(keyPair.getPublic(), spkac.getPublicKey());

    return spkac;
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetSPKACWithWrongChallenge() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException, OperatorCreationException, IOException {
    final JcaSignedPublicKeyAndChallenge spkac = buildSPKAC("ED448", 448, "1.3.101.113", "Hello");
    builder.setPublicKey(spkac, "<CHALLENGE>");
  }

  @Test(expected = InvalidKeyException.class)
  public void testSetED448KeySPKAC() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException, OperatorCreationException {
    final String challenge = "Hello";
    final JcaSignedPublicKeyAndChallenge spkac = buildSPKAC("ED448", 448, "1.3.101.113", challenge);
    builder.setPublicKey(spkac, challenge);
  }
}
