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

import javax.security.auth.x500.X500Principal;

/**
 * Constants available for reuse.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class Constants {

  /**
   * This represents the X.500 distinguished name for the issuer of WebID self-signed certificates.
   */
  public static final X500Principal WEBID_ISSUER = new X500Principal("O={}, CN=WebID");

  /**
   * This is the parameterized SPARQL query used to verify if the WebID profile contains the requested public key.
   */
  public static final String WEBID_CERT_SPARQL_QUERY = createWebIdCertQuery();

  private static String createWebIdCertQuery() {
    final String nl = System.getProperty("line.separator");

    StringBuilder queryBuilder = new StringBuilder();
    queryBuilder.append("PREFIX : <http://www.w3.org/ns/auth/cert#>").append(nl);
    queryBuilder.append("PREFIX XSD : <http://www.w3.org/2001/XMLSchema#>").append(nl);
    queryBuilder.append("ASK {").append(nl);
    queryBuilder.append("   ?webid :key [").append(nl);
    queryBuilder.append("      :modulus ?mod;").append(nl);
    queryBuilder.append("      :exponent ?exp").append(nl);
    queryBuilder.append("   ] .").append(nl);
    queryBuilder.append("}");

    return queryBuilder.toString();
  }
}
