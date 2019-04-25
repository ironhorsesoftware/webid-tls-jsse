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

import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.net.URLConnection;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.jena.rdf.model.Model;

/**
 * This implements an {@link X509ExtendedTrustManager} for WebID-TLS.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdTrustManager extends X509ExtendedTrustManager {

  private X509Certificate webIdRootCertificate;

  WebIdTrustManager() {
    webIdRootCertificate = new WebIdRootCertificate();
  }

  /**
   * Allows for certificate issuers with an X.500 Principal of <code>O={}, CN=WebID</code>.
   *
   * @return A single certificate with an accepted issuer and subject of {@link Constants#WebIdIssuer}.
   * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
   */
  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[]{ webIdRootCertificate };
  }

  /**
   * Checks the client certificate chain using the provided authentication algorithm.
   * This certificate will be checked against the {@link WebIdCertificateKeyStore} of known-valid certificates, and if not found,
   * an HTTP or HTTPS request will be made to the WebID Profile on the certificate to get the public key.  If one
   * or more public keys can be validated, the certificate will be trusted.  If not, a {@link CertificateException}
   * will be thrown. 
   *
   * @param certificateChain The provided certificate chain.
   * @param authenticationType The authentication type.
   * @throws CertificateException if the certificate is invalid.
   * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] certificateChain, String authenticationType) throws CertificateException {
    checkClientTrusted(certificateChain);
  }

  /**
   * Checks the client certificate chain using the provided authentication algorithm and socket.
   *
   * @param certificateChain The provided certificate chain.
   * @param authenticationType The authentication type.
   * @param socket The socket the connection is made over.
   * @throws CertificateException if the certificate is invalid.
   * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, java.net.Socket)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] certificateChain, String authenticationType, Socket socket) throws CertificateException {
    checkClientTrusted(certificateChain, authenticationType);
  }

  /**
   * Checks the client certificate chain using the provided authentication algorithm and SSL engine.
   *
   * @param certificateChain The provided certificate chain.
   * @param authenticationType The authentication type.
   * @param engine The SSL engine.
   * @throws CertificateException if the certificate is invalid.
   * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, javax.net.ssl.SSLEngine)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] certificateChain, String authenticationType, SSLEngine engine) throws CertificateException {
    checkClientTrusted(certificateChain, authenticationType);
  }

  /**
   * This method is used to check the server's certificate chain for authenticity.
   * WebID-TLS cannot be used for this purpose, so a {@link CertificateException} is thrown.
   *
   * @param certificateChain The server's certificate chain.
   * @param authenticationType The authentication mechanism.
   * @throws CertificateException as WebID-TLS cannot be used for server authentication.
   * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
   */
  @Override
  public void checkServerTrusted(X509Certificate[] certificateChain, String authenticationType) throws CertificateException {
    throw new CertificateException("WebID-TLS cannot be used for server authentication.");
  }

  /**
   * Throws a {@link CertificateException}, following {@link #checkServerTrusted(X509Certificate[], String)}.
   *
   * @see #checkServerTrusted(X509Certificate[], String)
   * @see javax.net.ssl.X509ExtendedTrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String, java.net.Socket)
   */
  @Override
  public void checkServerTrusted(X509Certificate[] certificateChain, String authenticationType, Socket socket) throws CertificateException {
    checkServerTrusted(certificateChain, authenticationType);
  }

  /**
   * Throws a {@link CertificateException}, following {@link #checkServerTrusted(X509Certificate[], String)}.
   *
   * @see #checkServerTrusted(X509Certificate[], String)
   * @see javax.net.ssl.X509ExtendedTrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String, javax.net.ssl.SSLEngine)
   */
  @Override
  public void checkServerTrusted(X509Certificate[] certificateChain, String authenticationType, SSLEngine engine) throws CertificateException {
    checkServerTrusted(certificateChain, authenticationType);
  }

  private void checkClientTrusted(X509Certificate[] certificateChain) throws CertificateException {
    for (final WebIdClaim claim : getWebIdClaims(certificateChain)) {
      // 1. TODO: Check claim in WebId KeyStore.

      // 2. Fetch the Web ID Profile and verify.
      checkClaim(getWebIdProfile(createWebIdProfileConnection(claim.getUri())), claim.getPublicKey());
    }
  }

  private List<WebIdClaim> getWebIdClaims(X509Certificate[] certificateChain) throws CertificateException {
    if ((certificateChain == null) || (certificateChain.length == 0)) {
      throw new CertificateException("The certificate chain is empty.");
    }

    final ArrayList<WebIdClaim> webIdList = new ArrayList<>(certificateChain.length);

    for (X509Certificate cert : certificateChain) {
      final Collection<List<?>> alternativeNames = cert.getSubjectAlternativeNames();

      if (alternativeNames == null) {
        continue;
      }

      for (List<?> alternativeName : alternativeNames) {
        try {
          // 6 indicates an alternative name represented as a URI
          // https://docs.oracle.com/javase/8/docs/api/java/security/cert/X509Certificate.html#getSubjectAlternativeNames--
          if ((Integer) alternativeName.get(0) == 6) {
            final URI webIdUri = new URI(alternativeName.get(1).toString().trim());
            webIdList.add(new WebIdClaim(cert, webIdUri));
          }
        } catch (Exception e) {
          throw new CertificateException("Malformed SubjectAlternateName URI for Certificate of Subject " + cert.getSubjectDN().getName(), e);
        }
      }
    }

    return webIdList;
  }

  private HttpURLConnection createWebIdProfileConnection(URI webId) throws CertificateException {
    if ((webId.getScheme() == null) || !webId.getScheme().equalsIgnoreCase("http") && !webId.getScheme().equalsIgnoreCase("https")) {
      throw new CertificateException("WebIDs can only be validated via HTTP or HTTPS. " + webId.toString() + " cannot be verified.");
    }

    final HttpURLConnection connection;

    try {
      // Massage the WebID Profile from the WebID URI.

      final URLConnection urlConnection = webId.toURL().openConnection();

      if (urlConnection instanceof HttpsURLConnection) {
        final HttpsURLConnection httpsConnection = (HttpsURLConnection) urlConnection;

        // Do stuff with the HTTPS connection.

        connection = httpsConnection;
      } else {
        connection = (HttpURLConnection) urlConnection;
      }

      // Do stuff with the HTTP connection.

    } catch (Exception e) {
      throw new CertificateException("Unable to construct a Web ID Profile connection to " + webId.toString(), e);
    }

    return connection;
  }

  private Model getWebIdProfile(HttpURLConnection connection) throws CertificateException {
    return null;
  }

  private void checkClaim(Model profile, PublicKey claimedKey) throws CertificateException {
    
  }
}
