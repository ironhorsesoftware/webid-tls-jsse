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
package com.ironhorsesoftware.jsse.webidtls;

import java.net.URI;
import java.security.PublicKey;

/**
 * This class represnets a 
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
final class WebIdClaim {
  private URI uri;
  private PublicKey publicKey;

  /**
   * Constructs a new WebID claim to validate.
   *
   * @param uri The URI representing the Web ID to validate.
   * @param publicKey The public key to use to validate the claim.
   */
  WebIdClaim(URI uri, PublicKey publicKey) {
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
  PublicKey getPublicKey() {
    return publicKey;
  }
}
