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
package com.ironhorsesoftware.jsse.webid;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;

import com.ironhorsesoftware.jsse.SniAndCertDnsKeyManager;
import com.ironhorsesoftware.jsse.webid.tls.WebIdTrustManagerFactory;

/**
 * Constructs an {@link SSLEngine} from the parameters provided.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class WebIdSSLEngineBuilder {

  private List<KeyStore.Builder> keyManagerKeyStoreBuilders;
  private String defaultAlias;

  private KeyStore trustManagerKeyStore;
  private KeyStoreBuilderParameters trustManagerKeyStoreParams;
  private boolean requireWebIdIssuedCertificates;

  /**
   * Initializes the builder.
   */
  public WebIdSSLEngineBuilder() {
    this.keyManagerKeyStoreBuilders = null;
    this.defaultAlias = null;
    this.trustManagerKeyStore = null;
    this.trustManagerKeyStoreParams = null;
    this.requireWebIdIssuedCertificates = true;
  }

  /**
   * Initializes the PKIX {@link KeyManagerFactory} with the provided
   * {@link KeyStore} and <code>password</code>.  If either this function
   * or {@link #setPkixKeyManagerFactoryParams(KeyStoreBuilderParameters)}
   * was already called, an {@link IllegalStateException} will be thrown.
   *
   * @param keyStore The key store to use with the key manager.
   * @param password The password needed to access the key manager.
   * @return This builder, for chaining.
   * @throws IllegalStateException if the key manager was already configured.
   * @throws IllegalArgumentException if <code>keyStore</code> is <code>null</code>.
   */
  public WebIdSSLEngineBuilder setPkixKeyManagerKeyStore(KeyStore keyStore, char[] password) {
    if (keyManagerKeyStoreBuilders != null) {
      throw new IllegalStateException("The Key Manager Factory was already configured.");

    } else if (keyStore == null) {
      throw new IllegalArgumentException("The Key Store cannot be null.");

    }

    this.keyManagerKeyStoreBuilders = new java.util.ArrayList<KeyStore.Builder>();
    keyManagerKeyStoreBuilders.add(KeyStore.Builder.newInstance(keyStore, new KeyStore.PasswordProtection(password)));

    return this;
  }

  /**
   * Initializes the PKIX {@link KeyManagerFactory} with the provided
   * {@link KeyStoreBuilderParameters}.  If either this function or
   * {@link #setPkixKeyManagerKeyStore(KeyStore, char[])} was already
   * called, an {@link IllegalStateException} will be thrown.
   *
   * @param params The <code>KeyStore</code> builder parameters to use with the key manager.
   * @return This builder, for chaining.
   * @throws IllegalStateException if the key manager was already configured.
   * @throws IllegalArgumentException if <code>params</code> is <code>null</code>.
   */
  public WebIdSSLEngineBuilder setPkixKeyManagerFactoryParams(KeyStoreBuilderParameters params) {
    if (keyManagerKeyStoreBuilders != null) {
      throw new IllegalStateException("The Key Manager Factory was already configured.");

    } else if (params == null) {
      throw new IllegalArgumentException("The parameters cannot be null.");
    }

    this.keyManagerKeyStoreBuilders = params.getParameters();

    return this;
  }

  /**
   * Sets the {@link KeyStore} the {@link WebIdTrustManager} should use when checking
   * if a client certificate was previously validated, and to add validated client
   * certificates to.  If both this method and
   * {@link #setWebIdTrustManagerFactoryParams(KeyStoreBuilderParameters)} are called,
   * the {@link WebIdTrustManagerFactory} will be initialized with both sets of arguments.
   *
   * @return This builder, for chaining.
   */
  public WebIdSSLEngineBuilder setWebIdTrustManagerFactoryKeyStore(KeyStore keyStore) {
    this.trustManagerKeyStore = keyStore;
    return this;
  }

  /**
   * Sets the {@link KeyStoreBuilderParameters} describing how to interact with the {@link KeyStore}s
   * the {@link WebIdTrustManager} should use when checking
   * if a client certificate was previously validated, and to add validated client
   * certificates to.  If both this method and
   * {@link #setWebIdTrustManagerFactoryKeyStore(KeyStore)} are called,
   * the {@link WebIdTrustManagerFactory} will be initialized with both sets of arguments.
   *
   * @return This builder, for chaining.
   */
  public WebIdSSLEngineBuilder setWebIdTrustManagerFactoryParams(KeyStoreBuilderParameters params) {
    this.trustManagerKeyStoreParams = params;
    return this;
  }

  /**
   * Sets the default alias the {@link SniAndCertDnsKeyManager} should return if an
   * alias could not be verified using either SNI or the client certificate's DNS
   * SubjectAlternativeNames.  This value defaults to (and may be) <code>null</code>
   * to indicate no alias should be returned.
   *
   * @param defaultAlias The default server alias for the SSL handshake, or <code>null</code> if none.
   * @return This builder, for chaining.
   */
  public WebIdSSLEngineBuilder setDefaultAlias(String defaultAlias) {
    this.defaultAlias = defaultAlias;
    return this;
  }

  /**
   * Returns whether the client must supply certificates
   * issued by the DN <code>CN=WebID, O={}</code>.
   *
   * The default is <code>true</code>.
   */
  public boolean areWebIdIssuedCertificatesRequired() {
    return requireWebIdIssuedCertificates;
  }

  /**
   * Sets whether the client must supply certificates
   * issued by the DN <code>CN=WebID, O={}</code>.
   *
   * @return This builder, for chaining.
   */
  public WebIdSSLEngineBuilder setRequireWebIdIssuedCertificates(boolean require) {
    this.requireWebIdIssuedCertificates = require;
    return this;
  }

  /**
   * Constructs the SSLEngine with:
   * <ul>
   *   <li>A {@link SniAndCertDnsKeyManager} wrapping the standard <code>PKIX</code> {@link X509ExtendedKeyManager}.</li>
   *   <li>A {@link WebIdTrustManager} for performing WebID-TLS authentication on client certificates.</li>
   *   <li>A <code>TLS</code> {@link SSLContext}.</li>
   *   <li>{@link SSLParameters#setWantClientAuth(boolean)} set to <code>true</code>.</li>
   *   <li>{@link SSLParameters#setUseCipherSuitesOrder(boolean)} set to <code>true</code>.</li>
   * </ul>
   *
   * @return The built <code>SSLEngine</code>
   * @throws NoSuchAlgorithmException If either a PKIX <code>KeyManagerFactory</code> or TLS <code>SSLContext</code> cannot be found.
   * @throws InvalidAlgorithmParameterException If either the key manager factory or trust manager factory parameters are invalid.
   * @throws KeyStoreException If either the key manager factory or trust manager factory keystores are invalid.
   * @throws KeyManagementException If a <code>X509ExtendedKeyManager</code> is not available, or the <code>SSLContext</code> could not be initialized.
   */
  public SSLEngine build() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, KeyManagementException {
    if (keyManagerKeyStoreBuilders == null) {
      throw new IllegalStateException("The key manager factory must be configured before building the SSLEngine.");

    } else if ((trustManagerKeyStore == null) && (trustManagerKeyStoreParams == null)) {
      throw new IllegalStateException("The trust manager factory must be configured before building the SSLEngine.");
    }

    final WebIdTrustManagerFactory tmf = new WebIdTrustManagerFactory();
    tmf.setRequireWebIdIssuedCertificates(requireWebIdIssuedCertificates);

    if (trustManagerKeyStore != null) {
      tmf.init(trustManagerKeyStore);
    }

    if (trustManagerKeyStoreParams != null) {
      tmf.init(trustManagerKeyStoreParams);
    }

    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
    kmf.init(new KeyStoreBuilderParameters(this.keyManagerKeyStoreBuilders));

    SniAndCertDnsKeyManager keyManager = null;

    for (KeyManager km : kmf.getKeyManagers()) {
      if (!(km instanceof X509ExtendedKeyManager)) {
        continue;
      }

      keyManager = new SniAndCertDnsKeyManager((X509ExtendedKeyManager) km, defaultAlias);
    }

    if (keyManager == null) {
      throw new KeyManagementException("No X509ExtendedKeyManager was created by the PKIX key factory.  This is needed to properly manage the SSLEngine.");
    }

    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(new KeyManager[] { keyManager }, tmf.getTrustManagers(), null);

    final SSLParameters sslParams = sslContext.getDefaultSSLParameters();

    // Tells the server to prefer the server's cipher suite preference, instead of the client's.
    // http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#cipher_suite_preference
    sslParams.setUseCipherSuitesOrder(true);

    /* This is required for WebID-TLS to function correctly.
     * 
     * WebID-TLS is about authentication, not security.  Likewise, we want to establish
     * the TLS connection even if the user does not provide a WebID-TLS certificate.
     * As a result, client authentication is wanted, not needed.
     */
    sslParams.setWantClientAuth(true);

    final SSLEngine engine = sslContext.createSSLEngine();
    engine.setSSLParameters(sslParams);

    return engine;
  }
}
