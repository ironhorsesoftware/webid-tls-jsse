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
package com.ironhorsesoftware.jsse;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * This class picks out a specific certificate when given a request that has
 * either an SNI hostname associated with it, or a client certificate with
 * a DNS Subject Alternative Name.  This is done through
 * {@link #chooseEngineServerAlias(String, Principal[], javax.net.ssl.SSLEngine)},
 * which under normal circumstances return null, but in this case should return
 * the server's alias.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class KeyManager extends X509ExtendedKeyManager {

  private X509ExtendedKeyManager parentKeyManager;
  private String defaultAlias;

  public KeyManager(X509ExtendedKeyManager parentKeyManager, String defaultAlias) {
    this.parentKeyManager = parentKeyManager;
    this.defaultAlias = defaultAlias;
  }

  /**
   * Forwards to the parent key manager.
   *
   * @param keyType The key type.
   * @param issuers The key issuers.
   * @param scoket The connection.
   * @return The client alias.
   * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[], java.security.Principal[], java.net.Socket)
   */
  @Override
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    return parentKeyManager.chooseClientAlias(keyType, issuers, socket);
  }

  @Override
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    return parentKeyManager.chooseEngineClientAlias(keyType, issuers, engine);
  }

  /**
   * Forwards to the parent key manager.
   *
   * @param keyType The key algorithm type name.
   * @param issuers The list of acceptable CA issuer subject names, or null if it does not matter which issuers are used.
   * @return
   * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String, java.security.Principal[])
   */
  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return parentKeyManager.getClientAliases(keyType, issuers);
  }

  /**
   * Forwards to the parent key manager.
   *
   * @param keyType The key type to look up server aliases by.
   * @param issuers The issuers of the allowable certificates.
   * @return The set of server aliases recognized with that combination.
   * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String, java.security.Principal[])
   */
  @Override
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return parentKeyManager.getServerAliases(keyType, issuers);
  }

  /**
   * Forwards to the parent key manager.
   *
   * @param alias The alias the certificate chain would be referenced by.
   * @return The certificate chain, or <code>null</code> are recognized by that alias.
   * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
   */
  @Override
  public X509Certificate[] getCertificateChain(String alias) {
    return parentKeyManager.getCertificateChain(alias);
  }

  /**
   * Forwards to the parent key manager.
   *
   * @param alias The alias the private key would be referenced by.
   * @return The private key, or <code>null</code> if none are recognized by that alias.
   * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
   */
  @Override
  public PrivateKey getPrivateKey(String alias) {
    return parentKeyManager.getPrivateKey(alias);
  }

  /**
   * 
   *
   * @param keyType The key type to check the authentication of.
   * @param issuers The issuers issuing the valid root certificates.
   * @param socket The socket containing the SSL session.
   * @return The server alias, or <code>null</code> if none could be found.
   * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String, java.security.Principal[], java.net.Socket)
   */
  @Override
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    String alias = null;

    if (socket instanceof SSLSocket) {
      final SSLSession session = ((SSLSocket) socket).getHandshakeSession();
      alias = chooseServerAliasFromSSLSession(session);
    }

    if (alias == null) {
      alias = parentKeyManager.chooseServerAlias(keyType, issuers, socket);
    }

    if (alias == null) {
      alias = defaultAlias;
    }

    return alias;
  }

  /**
   * 
   *
   * @param keyType The key type to check the authentication of.
   * @param issuers The issuers issuing the valid root certificates.
   * @param engine The SSL engine processing the request.
   * @return The server alias, or <code>null</code> if none could be found.
   * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String, java.security.Principal[], java.net.Socket)
   */
  @Override
  public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
    final SSLSession session = engine.getHandshakeSession();
    String alias = chooseServerAliasFromSSLSession(session);

    if (alias == null) {
      alias = parentKeyManager.chooseEngineServerAlias(keyType, issuers, engine);
    }

    if (alias == null) {
      alias = defaultAlias;
    }

    return alias;
  }

  private String chooseServerAliasFromSSLSession(SSLSession session) {
    String alias = null;

    if (session instanceof ExtendedSSLSession) {
      alias = chooseServerAliasFromSNI((ExtendedSSLSession) session);
    }

    if (alias == null) {
      try {
        alias = chooseServerAliasFromClientCertificate(session.getPeerCertificates());
      } catch (SSLPeerUnverifiedException e) {
        // Client did not provide a certificate chain.
        alias = null;
      }
    }

    return alias;
  }

  private String chooseServerAliasFromSNI(ExtendedSSLSession session) {
    String hostName = null;

    for (SNIServerName name : session.getRequestedServerNames()) {
      if (name.getType() == StandardConstants.SNI_HOST_NAME) {
        hostName = ((SNIHostName) name).getAsciiName();
        break;
      }
    }

    return (isRecognizedHostName(hostName)) ? hostName : null;
  }

  private String chooseServerAliasFromClientCertificate(Certificate[] clientCertificateChain) {
    String alias = null;

    if ((clientCertificateChain == null) || (clientCertificateChain.length == 0)) {
      return alias;
    }

    

    return alias;
  }

  private boolean isRecognizedHostName(String hostName) {
    if (hostName == null) {
      return false;
    }

    if (getCertificateChain(hostName) == null) {
      return false;
    }

    if (getPrivateKey(hostName) == null) {
      return false;
    }

    return true;
  }
}
