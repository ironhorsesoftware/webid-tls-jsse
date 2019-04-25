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

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.mozilla.jcajce.JcaSignedPublicKeyAndChallenge;

import com.ironhorsesoftware.jsse.webid.tls.Constants;

/**
 * This class is used to construct self-signed WebID X.509 certificates.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdX509CertificateBuilder {
  private X500Principal issuer;
  private String commonName;
  private JcaSignedPublicKeyAndChallenge spkac;
  private List<URI> webIds;
  private int yearsValid;

  public WebIdX509CertificateBuilder() {
    issuer = Constants.WEBID_ISSUER;
    commonName = null;
    spkac = null;
    webIds = new java.util.ArrayList<URI>();
    yearsValid = 5;
  }

  public String toString() {
    final String nl = System.getProperty("line.separator");

    StringBuilder builder = new StringBuilder("WebIdX509CertificateBuilder");
    builder.append(nl).append("\t     Issuer: ").append(issuer);
    builder.append(nl).append("\tCommon Name: ").append(commonName);
    builder.append(nl).append("\tYears Valid: ").append(yearsValid);

    builder.append(nl).append("\t    Web IDs: ");
    for (URI webId : webIds) {
      builder.append(nl).append("\t\t").append(webId);
    }

    builder.append(nl).append("\t      SPKAC: ");
    if (spkac != null) {
      builder.append(nl).append("\t\tChallenge: ").append(spkac.getChallenge());

      try {
        final String encodedSpkac = Base64.getEncoder().encodeToString(spkac.getEncoded());
        builder.append(nl).append("\t\t  SPKAC: ").append(encodedSpkac);
      } catch (IOException e) {
        builder.append(nl).append("\t\tSPKAC Encoding Failure: ").append(e.getMessage());
      }
    }

    return builder.toString();
  }
}
