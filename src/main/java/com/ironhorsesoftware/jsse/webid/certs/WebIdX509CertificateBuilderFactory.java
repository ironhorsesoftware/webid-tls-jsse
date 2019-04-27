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

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.ironhorsesoftware.jsse.webid.Constants;

/**
 * A factory of {@link WebIdX509CertificateBuilder}s.  This
 * will create a WebID root certificate using the public and
 * private keys provided, and all generated certificate builders
 * will use that root certificate to sign.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdX509CertificateBuilderFactory {

  private SecureRandom rng;

  private X509Certificate webIdRootCertificate;
  private PrivateKey webIdRootPrivateKey;

  private WebIdX509CertificateBuilderFactory() {
    rng = new SecureRandom();
    rng.setSeed(System.currentTimeMillis());
  }

  /**
   * Creates a <code>WebIdX509CertificateBuilderFactory</code> with the provided
   * {@link PublicKey} and {@link PrivateKey}.  The keys are used to generate a
   * self-signed root certificate with the {@link Constants#WEBID_ISSUER} subject,
   * for generated {@link WebIdX509CertificateBuilder}s to use as their certificate's
   * issuer.
   *
   * @param webIdRootPublicKey The public key to use when constructing the root certificate.
   * @param webIdRootPrivateKey The private key to use when constructing the root certificate.
   * @throws OperatorCreationException If unable to construct the root certificate.
   * @throws CertificateException If unable to construct the root certificate.
   * @throws CertIOException If unable to construct the root certificate.
   */
  public WebIdX509CertificateBuilderFactory(PublicKey webIdRootPublicKey, PrivateKey webIdRootPrivateKey) throws OperatorCreationException, CertificateException, CertIOException {
    this();

    this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(rng, webIdRootPublicKey, webIdRootPrivateKey); 
    this.webIdRootPrivateKey = webIdRootPrivateKey;
  }

  /**
   * Creates a <code>WebIdX509CertificateBuilderFactory</code> with the provided
   * {@link KeyPair}. The public and private keys in the pair are used to generate
   * a self-signed root certificate with the {@link Constants#WEBID_ISSUER} subject,
   * for generated {@link WebIdX509CertificateBuilder}s to use as their certificate's
   * issuer.
   *
   * @param keyPair The public & private key pair to use when constructing the root certificate.
   * @throws OperatorCreationException If unable to construct the root certificate.
   * @throws CertificateException If unable to construct the root certificate.
   * @throws CertIOException If unable to construct the root certificate.
   */
  public WebIdX509CertificateBuilderFactory(KeyPair keyPair) throws OperatorCreationException, CertificateException, CertIOException {
    this(keyPair.getPublic(), keyPair.getPrivate());
  }

  /**
   * Creates a <code>WebIdX509CertificateBuilderFactory</code> with the provided {@link X509Certificate} and
   * {@link PrivateKey}.  If the certificate already has a subject matching the {@link Constants#WEBID_ISSUER},
   * it is used verbatim when creating {@link WebIdX509CertificateBuilder}s.  If not, the public key in the
   * certificate is harvested, and used to create a new {@link X509Certificate} with the {@link Constants#WEBID_ISSUER}
   * subject.
   *
   * @param certificate The certificate to either use verbatim or harvest the {@link PublicKey} of.
   * @param privateKey The corresponding {@link PrivateKey}.
   * @throws CertIOException If unable to construct the root certificate from the harvested public key.
   * @throws CertificateException If unable to construct the root certificate from the harvested public key.
   * @throws OperatorCreationException If unable to construct the root certificate from the harvested public key.
   */
  public WebIdX509CertificateBuilderFactory(X509Certificate certificate, PrivateKey privateKey) throws CertIOException, CertificateException, OperatorCreationException {
    this();

    this.webIdRootPrivateKey = privateKey;

    if (certificate.getSubjectX500Principal().equals(Constants.WEBID_ISSUER)) {
      this.webIdRootCertificate = certificate;
    } else {
      this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(this.rng, certificate.getPublicKey(), this.webIdRootPrivateKey);
    }
  }

  /**
   * Creates a <code>WebIdX509CertificateBuilderFactory</code> by fetching an {@link X509Certificate} and
   * {@link PrivateKey} with the given <code>alias</code> from the provided {@link KeyStore}.  If the X.509
   * certificate already has a subject of {@link Constants#WEBID_ISSUER}, it is used verbatim.  Otherwise,
   * the {@link PublicKey} is harvested and used to create a new {@link X509Certificate} with that issuer. 
   *
   * @param keyStore The {@link KeyStore} to retrieve the {@link PrivateKey} and {@link Certificate} from.
   * @param alias The alias of the {@link Certificate} and {@link PrivateKey} to retrieve.
   * @param password The password to use when retrieving the {@link PrivateKey} from the {@link KeyStore}.
   * @throws UnrecoverableKeyException If unable to retrieve either the {@link Certificate} or {@link PrivateKey} from the {@link KeyStore}.
   * @throws KeyStoreException If unable to retrieve either the {@link Certificate} or {@link PrivateKey} from the {@link KeyStore}.
   * @throws NoSuchAlgorithmException If unable to retrieve either the {@link Certificate} or {@link PrivateKey} from the {@link KeyStore}.
   * @throws CertIOException If unable to construct the root certificate from the harvested {@link PublicKey}.
   * @throws CertificateException If unable to construct the root certificate from the harvested {@link PublicKey}.
   * @throws OperatorCreationException If unable to construct the root certificate from the harvested {@link PublicKey}.
   * @throws IllegalArgumentException if the given alias does not map to a {@link PrivateKey} and {@link X509Certificate} in the {@link KeyStore}.
   */
  public WebIdX509CertificateBuilderFactory(KeyStore keyStore, String alias, char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertIOException, CertificateException, OperatorCreationException {
    this();

    final Key key = keyStore.getKey(alias, password);

    if ((key == null) || !(key instanceof PrivateKey)) {
      throw new IllegalArgumentException("Key \"" + alias + "\" either does not exist or is not a private key.");
    }

    final Certificate cert = keyStore.getCertificate(alias);
    if ((cert == null) || !(cert instanceof X509Certificate)) {
      throw new IllegalArgumentException("Certificate \"" + alias + "\" either does not exist or is not an X.509 Certificate.");
    }

    this.webIdRootPrivateKey = (PrivateKey) key;

    final X509Certificate certificate = (X509Certificate) cert;
    if (certificate.getSubjectX500Principal().equals(Constants.WEBID_ISSUER)) {
      this.webIdRootCertificate = certificate;
    } else {
      this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(this.rng, certificate.getPublicKey(), this.webIdRootPrivateKey);
    }
    
  }

  private static X509Certificate createWebIdRootSelfSignedCertificate(SecureRandom rng, PublicKey publicKey, PrivateKey privateKey) throws CertIOException, CertificateException, OperatorCreationException {
    final long now = System.currentTimeMillis();

    final JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            Constants.WEBID_ISSUER,
            BigInteger.valueOf(rng.nextLong()),
            new Date(now - Constants.ONE_HOUR_IN_MILLIS),
            new Date(now + Constants.TWENTY_YEARS_IN_MILLIS),
            Constants.WEBID_ISSUER,
            publicKey);

    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));  

    final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM_SHA512withRSA);

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    return converter.getCertificate(builder.build(signerBuilder.build(privateKey)));
  }

  /**
   * Constructs a new {@link WebIdX509CertificateBuilder} with the generated root
   * {@link X509Certificate} and {@link PrivateKey} for {@link Constants#WEBID_ISSUER}.
   *
   * @return A new instance of <code>WebIdX509CertificateBuilder</code>.
   */
  public WebIdX509CertificateBuilder newCertificateBuilder() {
    return new WebIdX509CertificateBuilder(webIdRootCertificate, webIdRootPrivateKey, rng);
  }

  X509Certificate getWebIdRootCertificate() {
    return this.webIdRootCertificate;
  }

  PrivateKey getWebIdRootPrivateKey() {
    return this.webIdRootPrivateKey;
  }
}
