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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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

  private static long ONE_HOUR = 60L * 60L * 1000L;
  private static long TWENTY_YEARS = 20L * 366L * 24L * 60L * 60L * 1000L;

  private SecureRandom rng = new SecureRandom();
  private BouncyCastleProvider provider = new BouncyCastleProvider();

  private X509Certificate webIdRootCertificate;
  private PrivateKey webIdRootPrivateKey;

  public WebIdX509CertificateBuilderFactory(PublicKey webIdRootPublicKey, PrivateKey webIdRootPrivateKey) throws OperatorCreationException, CertificateException, CertIOException {

    final long now = System.currentTimeMillis();

    final JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            Constants.WEBID_ISSUER,
            BigInteger.valueOf(rng.nextLong()),
            new Date(now - ONE_HOUR),
            new Date(now + TWENTY_YEARS),
            Constants.WEBID_ISSUER,
            webIdRootPublicKey);

    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));  

    final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA512withRSA");
    signerBuilder.setProvider(provider);

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

    this.webIdRootCertificate = converter.getCertificate(builder.build(signerBuilder.build(webIdRootPrivateKey)));
    this.webIdRootPrivateKey = webIdRootPrivateKey;
  }

  public WebIdX509CertificateBuilder newWebIdX509CertificateBuilder() {
    return new WebIdX509CertificateBuilder(provider, webIdRootCertificate, webIdRootPrivateKey);
  }
}
