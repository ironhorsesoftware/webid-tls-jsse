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
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.ironhorsesoftware.jsse.webid.Constants;

/**
 * This class is used to construct self-signed WebID X.509 certificates.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdX509CertificateBuilder {
  private Provider provider;
  private X509Certificate issuerCert;
  private PrivateKey issuerPrivateKey;
  private SecureRandom rng;

  private String commonName;
  private String emailAddress;
  private RSAPublicKey publicKey;
  private List<URI> webIds;
  private int yearsValid;

  WebIdX509CertificateBuilder(X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
    this.provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    this.rng = new SecureRandom();
    this.issuerCert = issuerCertificate;
    this.issuerPrivateKey = issuerPrivateKey;

    this.commonName = null;
    this.emailAddress = null;
    this.publicKey = null;
    this.webIds = new java.util.ArrayList<URI>();
    this.yearsValid = 5;
  }

  public WebIdX509CertificateBuilder setCommonName(String commonName) {
    if (commonName == null) {
      throw new IllegalArgumentException("The common name cannot be null.");
    }
    commonName = commonName.trim();
    if (commonName.isEmpty()) {
      throw new IllegalArgumentException("The common name (\"" + commonName + "\") cannot be blank.");
    }

    this.commonName = commonName;

    return this;
  }

  public WebIdX509CertificateBuilder setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress;

    return this;
  }

  public void setPublicKey(RSAPublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public WebIdX509CertificateBuilder setPublicKey(JcaSignedPublicKeyAndChallenge spkac) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
    final PublicKey publicKey = spkac.getPublicKey();
    if (publicKey instanceof RSAPublicKey) {
       setPublicKey((RSAPublicKey) publicKey);
    } else {
      throw new InvalidKeyException("An RSA Public Key is required for WebID certificates.");
    }

    return this;
  }

  public WebIdX509CertificateBuilder addWebId(URI webId) {
    webIds.add(webId);

    return this;
  }

  public WebIdX509CertificateBuilder clearWebIds() {
    webIds.clear();

    return this;
  }

  public WebIdX509CertificateBuilder setYearsValid(int years) {
    if ((years < 1) || (years > 20)) {
      throw new IllegalArgumentException(years + " is not a valid number of years. Number of years must be between 1 and 20, inclusive.");
    }

    this.yearsValid = years;

    return this;
  }

  /**
   * Constructs a new X.509 WebID Self-Signed Certificate from the provided information.
   * 
   *
   * @return
   * @throws CertIOException If unable to create the certificate.
   * @throws OperatorCreationException 
   * @throws CertificateException 
   * @throws IllegalStateException if the builder is not correctly configured.
   */
  public X509Certificate build() throws CertIOException, CertificateException, OperatorCreationException {
    checkValidity();

    final long now = System.currentTimeMillis();

    final JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            this.issuerCert,                                  // Issuer
            BigInteger.valueOf(rng.nextLong()),               // Serial Number
            new Date(now - Constants.ONE_HOUR_IN_MILLIS),     // Valid Starting
            new Date(now + Constants.TWENTY_YEARS_IN_MILLIS), // Valid Until
            this.issuerCert.getSubjectX500Principal(),        // Subject
            this.publicKey);                                  // Public Key

    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyAgreement));

    builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

    final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA512withRSA");
    signerBuilder.setProvider(provider);

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

    return converter.getCertificate(builder.build(signerBuilder.build(issuerPrivateKey)));
  }

  public void checkValidity() throws IllegalStateException {
    if ((commonName == null) || (commonName.isEmpty())) {
      throw new IllegalStateException("The common name must be specified.");
    }

    if (publicKey == null) {
      throw new IllegalStateException("The public key cannot be null.");
    }

    if ((webIds == null) || webIds.isEmpty()) {
      throw new IllegalStateException("There must be at least one WebID URI.");
    }

    if ((yearsValid < 1) || (yearsValid > 20)) {
      throw new IllegalStateException("The certificate must be valid for at least 1 year, but no more than 20 years.");
    }
  }

  public String toString() {
    final String nl = System.getProperty("line.separator");

    StringBuilder builder = new StringBuilder("WebIdX509CertificateBuilder");
    builder.append(nl).append("\t     Issuer: ").append(issuerCert.getSubjectDN());
    builder.append(nl).append("\tCommon Name: ").append(commonName);
    builder.append(nl).append("\t      Email: ").append(emailAddress);
    builder.append(nl).append("\tYears Valid: ").append(yearsValid);

    builder.append(nl).append("\t    Web IDs: ");
    for (URI webId : webIds) {
      builder.append(nl).append("\t\t").append(webId);
    }

    builder.append(nl).append("\t Public Key: ");
    if (publicKey != null) {
      builder.append(nl).append("\t\tAlgorithm: RSA");
      builder.append(nl).append("\t\t  Modulus: ").append(publicKey.getModulus());
      builder.append(nl).append("\t\t Exponent: ").append(publicKey.getPublicExponent());
    }

    return builder.toString();
  }
}
