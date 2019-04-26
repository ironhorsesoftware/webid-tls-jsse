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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

  private SecureRandom rng = new SecureRandom();
  private Provider provider = new BouncyCastleProvider();

  private X509Certificate webIdRootCertificate;
  private PrivateKey webIdRootPrivateKey;

  public WebIdX509CertificateBuilderFactory(PublicKey webIdRootPublicKey, PrivateKey webIdRootPrivateKey) throws OperatorCreationException, CertificateException, CertIOException {
    this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(provider, rng, webIdRootPublicKey, webIdRootPrivateKey); 
    this.webIdRootPrivateKey = webIdRootPrivateKey;
  }

  public WebIdX509CertificateBuilderFactory(X509Certificate certificate, PrivateKey privateKey) throws CertIOException, CertificateException, OperatorCreationException {
    this.webIdRootPrivateKey = privateKey;

    if (certificate.getSubjectDN().equals(Constants.WEBID_ISSUER)) {
      this.webIdRootCertificate = certificate;
    } else {
      this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(this.provider, this.rng, certificate.getPublicKey(), this.webIdRootPrivateKey);
    }
  }

  public WebIdX509CertificateBuilderFactory(KeyStore keyStore, String alias, char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertIOException, CertificateException, OperatorCreationException {
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
    if (certificate.getSubjectDN().equals(Constants.WEBID_ISSUER)) {
      this.webIdRootCertificate = certificate;
    } else {
      this.webIdRootCertificate = createWebIdRootSelfSignedCertificate(this.provider, this.rng, certificate.getPublicKey(), this.webIdRootPrivateKey);
    }
    
  }

  private static X509Certificate createWebIdRootSelfSignedCertificate(Provider provider, SecureRandom rng, PublicKey publicKey, PrivateKey privateKey) throws CertIOException, CertificateException, OperatorCreationException {
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
    signerBuilder.setProvider(provider);

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    return converter.getCertificate(builder.build(signerBuilder.build(privateKey)));
  }

  public WebIdX509CertificateBuilder newWebIdX509CertificateBuilder() {
    return new WebIdX509CertificateBuilder(webIdRootCertificate, webIdRootPrivateKey);
  }
}
