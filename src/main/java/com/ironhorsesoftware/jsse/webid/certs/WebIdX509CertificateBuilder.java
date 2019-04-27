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
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
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

  private X500Principal subject;
  private String emailAddress;
  private RSAPublicKey publicKey;
  private List<URI> webIds;
  private int yearsValid;

  WebIdX509CertificateBuilder(X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) {
    this.provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    this.issuerCert = issuerCertificate;
    this.issuerPrivateKey = issuerPrivateKey;

    this.rng = new SecureRandom();
    this.rng.setSeed(System.currentTimeMillis());

    this.subject = null;
    this.emailAddress = null;
    this.publicKey = null;
    this.webIds = new java.util.ArrayList<URI>();
    this.yearsValid = 5;
  }

  /**
   * Sets the common name used in the certificate's subject.
   *
   * @param commonName The common name to be added to the certificate.
   * @return This builder, for chaining.
   * @throws IllegalArgumentException If the common name is null, empty, or improperly named.
   */
  public WebIdX509CertificateBuilder setCommonName(String commonName) {
    if (commonName == null) {
      throw new IllegalArgumentException("The common name cannot be null.");
    }

    commonName = commonName.trim();
    if (commonName.isEmpty()) {
      throw new IllegalArgumentException("The common name (\"" + commonName + "\") cannot be blank.");
    }

    final StringBuilder subjectBuilder = new StringBuilder(commonName.length()+17);
    subjectBuilder.append("CN=").append(commonName).append(",O=Solid.VIP");

    this.subject = new X500Principal(subjectBuilder.toString());
    return this;
  }

  /**
   * Sets the e-mail address.  If one is provided and not empty, it is used
   * as an Subject Alternate Name of type RFC822 in the certificate.
   *
   * @param emailAddress The e-mail address to store in the certificate.
   * @return This builder, for chaining.
   * @throws IllegalArgumentException If the email address is empty.
   */
  public WebIdX509CertificateBuilder setEmailAddress(String emailAddress) {
    if (emailAddress != null) {
      emailAddress = emailAddress.trim();

      if (emailAddress.isEmpty()) {
        throw new IllegalArgumentException("The email address cannot be empty.");
      }
    }

    this.emailAddress = emailAddress;
    return this;
  }

  /**
   * Sets the public key to be used in the certificate.  Since only RSA Public Keys
   * can be validated as part of WebID-TLS, an {@link RSAPublicKey} must be provided.
   *
   * @param publicKey The public key.
   * @return This builder, for chaining.
   * @throws IllegalArgumentException if <code>publicKey</code> is <code>null</code>.
   */
  public WebIdX509CertificateBuilder setPublicKey(RSAPublicKey publicKey) {
    if (publicKey == null) {
      throw new IllegalArgumentException("The public key cannot be null.");
    }

    this.publicKey = publicKey;
    return this;
  }

  /**
   * Sets the public key using a Signed Public Key and Challenge (SPKAC) as provided
   * by the <code>keygen</code> element on the HTML form.  The key must be generated
   * using RSA, and must also pass validation.
   *
   * @param spkac The SPKAC to verify, and use the {@link RSAPublicKey} of.
   * @return This builder, for chaining.
   * @throws InvalidKeyException If the key is not valid.
   * @throws NoSuchAlgorithmException If the algorithm is not recognized.
   * @throws NoSuchProviderException If the SPKAC's provider is not recognized.
   * @throws InvalidKeySpecException If the key specification is invalid.
   * @throws SignatureException If the signature could not be verified.
   * @throws IllegalArgumentException if <code>spkac</code> is <code>null</code> or does not represent an RSA Public Key.
   */
  public WebIdX509CertificateBuilder setPublicKey(JcaSignedPublicKeyAndChallenge spkac) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, SignatureException {
    if (spkac == null) {
      throw new IllegalArgumentException("The SPKAC cannot be null.");
    }

    spkac.setProvider(provider);

    // Verifies the SPKAC.
    final NetscapeCertRequest certRequest =
        new NetscapeCertRequest(spkac.getChallenge(), spkac.getSubjectPublicKeyInfo().getAlgorithm(), spkac.getPublicKey());

    final byte[] challenge = new byte[1024];
    rng.nextBytes(challenge);

    if (!certRequest.verify(Base64.getEncoder().encodeToString(challenge))) {
      throw new IllegalArgumentException("The SPKAC public key could not be verified.");
    }

    final PublicKey publicKey = spkac.getPublicKey();

    if (publicKey instanceof RSAPublicKey) {
       setPublicKey((RSAPublicKey) publicKey);

    } else {
      throw new InvalidKeyException("An RSA Public Key is required for WebID certificates.");
    }

    return this;
  }

  /**
   * Adds a new WebID which will be included in the Subject Alternate Names section
   * of the generated X.509 Certificate.  The URI must have an HTTP or HTTPS scheme
   * so the WebID Profile can be queried for the public key.
   *
   * @param webId The WebID to link in any generated certificates.
   * @return This builder, for chaining.
   * @throws IllegalArgumentException If the <code>webId</code> is <code>null</code> or does not have an HTTP or HTTPS scheme.
   */
  public WebIdX509CertificateBuilder addWebId(URI webId) {
    if ((webId == null)
        || (!webId.getScheme().equalsIgnoreCase(Constants.WEBID_URI_SCHEME_HTTP)
            && !webId.getScheme().equalsIgnoreCase(Constants.WEBID_URI_SCHEME_HTTPS))) {

      throw new IllegalArgumentException("The URI scheme must be either HTTP or HTTPS.  WebID " + webId + " is not valid.");
    }

    webIds.add(webId);
    return this;
  }

  /**
   * Clears all WebIDs added to this builder.
   *
   * @return This builder, for chaining.
   */
  public WebIdX509CertificateBuilder clearWebIds() {
    webIds.clear();
    return this;
  }

  /**
   * Sets the number of years this certificate will be valid for.
   * Must be between 1 and 20, inclusive.
   *
   * @param years The number of years the certificate will be valid for.
   * @return This builder, for chaining.
   * @throws IllegalArgumentException If the number of years is less than 1 or greater than 20.
   */
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
            this.issuerCert,                              // Issuer
            BigInteger.valueOf(rng.nextLong()),           // Serial Number
            new Date(now - Constants.ONE_HOUR_IN_MILLIS), // Valid Starting
            new Date(now + calculateMillisValid()),       // Valid Until
            this.subject,                                 // Subject
            this.publicKey);                              // Public Key

    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyEncipherment));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyAgreement));

    builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));

    if (this.emailAddress != null) {
      builder.addExtension(Extension.subjectAlternativeName, false, new GeneralName(GeneralName.rfc822Name, this.emailAddress));
    }

    for (URI webId : webIds) {
      builder.addExtension(Extension.subjectAlternativeName, false, new GeneralName(GeneralName.uniformResourceIdentifier, webId.toString()));
    }

    final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM_SHA512withRSA);
    signerBuilder.setProvider(provider);

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

    return converter.getCertificate(builder.build(signerBuilder.build(issuerPrivateKey)));
  }

  public void checkValidity() throws IllegalStateException {
    if (subject == null) {
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
    builder.append(nl).append("\t    Subject: ").append(subject);
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

  private long calculateMillisValid() {
    return ((long) (this.yearsValid * Constants.APPROX_DAYS_IN_YEAR)) * Constants.ONE_DAY_IN_MILLIS;
  }
}
