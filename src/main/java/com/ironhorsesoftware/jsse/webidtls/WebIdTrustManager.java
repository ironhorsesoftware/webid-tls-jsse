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

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * This implements an {@link X509ExtendedTrustManager} for WebID-TLS.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class WebIdTrustManager extends X509ExtendedTrustManager {

  WebIdTrustManager() {
  }

  /**
   * 
   * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] certificateChain, String authType) throws CertificateException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
   */
  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return null;
  }

  /**
   * 
   * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, java.net.Socket)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] arg0, String arg1, Socket arg2) throws CertificateException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see javax.net.ssl.X509ExtendedTrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String, javax.net.ssl.SSLEngine)
   */
  @Override
  public void checkClientTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2) throws CertificateException {
    // TODO Auto-generated method stub

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

}
