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
package com.ironhorsesoftware.jsse.webid.tls;

import java.net.URI;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * This class represnets a 
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
final class WebIdClaim {
  private X509Certificate certificate;
  private URI uri;
  private RSAPublicKey publicKey;

  /**
   * Constructs a new WebID claim to validate.
   *
   * @param certificate The certificate representing the claim.
   * @param uri The URI representing the Web ID to validate.
   */
  WebIdClaim(X509Certificate certificate, URI uri, RSAPublicKey publicKey) {
    this.certificate = certificate;
    this.uri = uri;
    this.publicKey = publicKey;
  }

  /**
   * The Universal Resource Indicator in the Subject Alternative Name
   * of the X.509 Certificate used to validate this WebID claim.
   *
   * @return the {@link URI}.
   */
  URI getUri() {
    return uri;
  }

  /**
   * The Public Key in the X.509 Certificate used to validate this WebID claim.
   *
   * @return the {@link PublicKey}.
   */
  RSAPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * The X.509 Certificate representing this claim.
   *
   * @return the {@link X509Certificate}.
   */
  X509Certificate getCertificate() {
    return certificate;
  }
}
