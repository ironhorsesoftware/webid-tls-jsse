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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.Constants;

/**
 * Tests the {@link WebIdX509CertificateBuilder}.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class WebIdX509CertificateBuilderTest {

  private static final String VALID_CN = "Michael Pigott";
  private static final String VALID_EMAIL = "mpigott@ironhorsesoftware.tech";
  private static final String VALID_URI = "https://www.ironhorsesoftware.com/profile#me";

  private static final long FIFTY_NINE_MINUTES_AGO_IN_MILLIS = 59 * 60 * 100;

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
    assertTrue(ncr.verify(challenge));

    final JcaSignedPublicKeyAndChallenge spkac = new JcaSignedPublicKeyAndChallenge(ncr.toASN1Primitive().getEncoded());

    assertEquals(challenge, spkac.getChallenge());
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

  @Test(expected = IllegalArgumentException.class)
  public void testAddNullWebId() {
    builder.addWebId(null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAddWebIdWrongScheme() throws URISyntaxException {
    builder.addWebId(new URI("file:///tmp/profile.jsonld"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetNegativeValidYears() {
    builder.setYearsValid(-1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetZeroValidYears() {
    builder.setYearsValid(0);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetValidYearsMoreThan20() {
    builder.setYearsValid(21);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSetEmptyEmail() {
    builder.setEmailAddress("  ");
  }

  @Test(expected = IllegalStateException.class)
  public void testEmptyBuilder() {
    builder.checkValidity();
  }

  @Test(expected = IllegalStateException.class)
  public void testSetOnlySubject() {
    builder.setCommonName(VALID_CN);
    builder.checkValidity();
  }

  @Test(expected = IllegalStateException.class)
  public void testSetOnlyRSAPublicKey() {
    final RSAPublicKey publicKey = (RSAPublicKey) keyGen.generateKeyPair().getPublic();
    builder.setPublicKey(publicKey);
    builder.checkValidity();
  }

  @Test(expected = IllegalStateException.class)
  public void testSetOnlySPKAC() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException {
    final String challenge = "I challenge you to a duel!";
    final JcaSignedPublicKeyAndChallenge spkac = buildSPKAC("RSA", 2048, "1.2.840.113549.1.1.10", challenge);
    builder.setPublicKey(spkac, challenge);
    builder.checkValidity();
  }

  @Test(expected = IllegalStateException.class)
  public void testSetOnlyWebId() throws URISyntaxException {
    builder.addWebId(new URI(VALID_URI));
    builder.checkValidity();
  }

  @Test(expected = IllegalStateException.class)
  public void testSetOnlyEmail() {
    builder.setEmailAddress(VALID_EMAIL);
    builder.checkValidity();
  }

  @Test
  public void testCheckValidityWithRSAKey() throws URISyntaxException {
    final RSAPublicKey publicKey = (RSAPublicKey) keyGen.generateKeyPair().getPublic();

    builder.setCommonName(VALID_CN);
    builder.setPublicKey(publicKey);
    builder.addWebId(new URI(VALID_URI));
    builder.setYearsValid(1);

    builder.checkValidity();
  }

  @Test
  public void testCheckValidityWithSPKAC() throws URISyntaxException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException {
    final String challenge = "I challenge you to a duel!";
    final JcaSignedPublicKeyAndChallenge spkac = buildSPKAC("RSA", 2048, "1.2.840.113549.1.1.10", challenge);

    builder.setCommonName(VALID_CN);
    builder.setPublicKey(spkac, challenge);
    builder.addWebId(new URI(VALID_URI));
    builder.setYearsValid(20);

    builder.checkValidity();
  }

  private void verifyCertificateInvariants(X509Certificate certificate) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    certificate.checkValidity();
    certificate.checkValidity(new Date(System.currentTimeMillis() - FIFTY_NINE_MINUTES_AGO_IN_MILLIS));
    assertEquals(Constants.WEBID_ISSUER, certificate.getIssuerX500Principal());

    final boolean[] keyUsage = certificate.getKeyUsage();
    assertNotNull(keyUsage);
    assertEquals(9, keyUsage.length);
    assertTrue(keyUsage[0]);  // digitalSignature
    assertTrue(keyUsage[1]);  // nonRepudiation
    assertTrue(keyUsage[2]);  // keyEncipherment
    assertFalse(keyUsage[3]); // dataEncipherment
    assertTrue(keyUsage[4]);  // keyAgreement
    assertFalse(keyUsage[5]); // keyCertSign
    assertFalse(keyUsage[6]); // crlSign
    assertFalse(keyUsage[7]); // encipherOnly
    assertFalse(keyUsage[8]); // decipherOnly

    final List<String> extendedKeyUsages = certificate.getExtendedKeyUsage();
    assertEquals(1, extendedKeyUsages.size());
    assertEquals(KeyPurposeId.id_kp_clientAuth.toOID().toString(), extendedKeyUsages.get(0));
  }

  private long approximateValidUntil(int yearsValid) {
    long numMillis = ((long) (yearsValid * Constants.APPROX_DAYS_IN_YEAR)) * Constants.ONE_DAY_IN_MILLIS;
    return numMillis - Constants.ONE_HOUR_IN_MILLIS;
  }

  @Test
  public void testBuildCertificateWithRSAKeyAndEmail() throws URISyntaxException, CertIOException, CertificateException, OperatorCreationException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final X500Principal subject = new X500Principal("CN=" + VALID_CN + ",O=Solid.VIP");
    final RSAPublicKey publicKey = (RSAPublicKey) keyGen.generateKeyPair().getPublic();
    final int yearsValid = 1;

    builder.setCommonName(VALID_CN);
    builder.setEmailAddress(VALID_EMAIL);
    builder.setPublicKey(publicKey);
    builder.addWebId(new URI(VALID_URI));
    builder.setYearsValid(yearsValid);

    final X509Certificate certificate = builder.build();
    certificate.verify(factory.getWebIdRootCertificate().getPublicKey());

    assertEquals(subject, certificate.getSubjectX500Principal());
    assertEquals(publicKey, certificate.getPublicKey());

    final Collection<List<?>> subjectAlternateNames = certificate.getSubjectAlternativeNames();
    assertEquals(2, subjectAlternateNames.size());

    for (List<?> san : subjectAlternateNames) {
      final Integer type = (Integer) san.get(0);
      switch (type.intValue()) {
        case 1:  assertEquals(VALID_EMAIL, san.get(1).toString()); break; // rfc822
        case 6:  assertEquals(VALID_URI, san.get(1).toString()); break;   // uniformResourceIdentifier
        default: fail("Unrecognized subject alternative name of type " + type);
      }
    }

    certificate.checkValidity(new Date(System.currentTimeMillis() + approximateValidUntil(yearsValid)));

    verifyCertificateInvariants(certificate);
  }

  @Test
  public void testBuildCertificateWithSPKAC() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, URISyntaxException, CertificateException {
    final X500Principal subject = new X500Principal("CN=" + VALID_CN + ",O=Solid.VIP");
    final int yearsValid = 20;

    final String challenge = "I challenge you to a duel!";
    final JcaSignedPublicKeyAndChallenge spkac = buildSPKAC("RSA", 2048, "1.2.840.113549.1.1.10", challenge);

    builder.setCommonName(VALID_CN);
    builder.setPublicKey(spkac, challenge);
    builder.addWebId(new URI(VALID_URI));
    builder.setYearsValid(yearsValid);

    final X509Certificate certificate = builder.build();
    certificate.verify(factory.getWebIdRootCertificate().getPublicKey());

    assertEquals(subject, certificate.getSubjectX500Principal());
    assertEquals(spkac.getPublicKey(), certificate.getPublicKey());

    final Collection<List<?>> subjectAlternateNames = certificate.getSubjectAlternativeNames();
    assertEquals(1, subjectAlternateNames.size());

    for (List<?> san : subjectAlternateNames) {
      final Integer type = (Integer) san.get(0);
      switch (type.intValue()) {
        case 6:  assertEquals(VALID_URI, san.get(1).toString()); break; // uniformResourceIdentifier
        default: fail("Unrecognized subject alternative name of type " + type);
      }
    }

    certificate.checkValidity(new Date(System.currentTimeMillis() + approximateValidUntil(yearsValid)));

    verifyCertificateInvariants(certificate);
  }

  @Test
  public void testBuildCertificateWithDnsNames() throws OperatorCreationException, CertificateException, CertIOException, URISyntaxException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    List<String> serverDnsNames = new java.util.ArrayList<>();
    serverDnsNames.add("webid");
    serverDnsNames.add("webid.ironhorsesoftware.com");

    final WebIdX509CertificateBuilderFactory factory =
        new WebIdX509CertificateBuilderFactory(keyGen.generateKeyPair());
    factory.addServerDnsNames(serverDnsNames);

    final WebIdX509CertificateBuilder builder = factory.newCertificateBuilder();

    final X500Principal subject = new X500Principal("CN=" + VALID_CN + ",O=Solid.VIP");
    final RSAPublicKey publicKey = (RSAPublicKey) keyGen.generateKeyPair().getPublic();

    builder.setCommonName(VALID_CN);
    builder.setEmailAddress(null);
    builder.setPublicKey(publicKey);
    builder.addWebId(new URI(VALID_URI));

    final X509Certificate certificate = builder.build();
    certificate.verify(factory.getWebIdRootCertificate().getPublicKey());

    assertEquals(subject, certificate.getSubjectX500Principal());
    assertEquals(publicKey, certificate.getPublicKey());

    final Collection<List<?>> subjectAlternateNames = certificate.getSubjectAlternativeNames();
    assertEquals(serverDnsNames.size() + 2, subjectAlternateNames.size());

    for (List<?> san : subjectAlternateNames) {
      final Integer type = (Integer) san.get(0);
      switch (type.intValue()) {
        case 2: assertTrue(serverDnsNames.contains(san.get(1)));         break; // dNSName
        case 4:  assertEquals("O=Solid.VIP,CN=" + VALID_CN, san.get(1)); break; // directoryName 
        case 6:  assertEquals(VALID_URI, san.get(1));                    break; // uniformResourceIdentifier
        default: fail("Unrecognized subject alternative name of type " + type + " and value " + san.get(1));
      }
    }

    certificate.checkValidity(new Date(System.currentTimeMillis() + approximateValidUntil(5))); // 5 is the default.

    verifyCertificateInvariants(certificate);
  }
}
