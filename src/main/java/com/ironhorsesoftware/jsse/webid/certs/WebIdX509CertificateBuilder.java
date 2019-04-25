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

import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;

/**
 * This class is used to construct self-signed WebID X.509 certificates.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdX509CertificateBuilder {
  private JcaSignedPublicKeyAndChallenge pbkac;

}
