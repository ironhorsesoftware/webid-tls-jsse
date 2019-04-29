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

  public WebIdSSLEngineBuilder() {
    this.keyManagerKeyStoreBuilders = null;
    this.defaultAlias = null;
    this.trustManagerKeyStore = null;
    this.trustManagerKeyStoreParams = null;
  }

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

  public WebIdSSLEngineBuilder setPkixKeyManagerFactoryParams(KeyStoreBuilderParameters params) {
    if (keyManagerKeyStoreBuilders != null) {
      throw new IllegalStateException("The Key Manager Factory was already configured.");

    } else if (params == null) {
      throw new IllegalArgumentException("The parameters cannot be null.");
    }

    this.keyManagerKeyStoreBuilders = params.getParameters();

    return this;
  }

  public WebIdSSLEngineBuilder setWebIdTrustManagerFactoryKeyStore(KeyStore keyStore) {
    this.trustManagerKeyStore = keyStore;
    return this;
  }

  public WebIdSSLEngineBuilder setWebIdTrustManagerFactoryParams(KeyStoreBuilderParameters params) {
    this.trustManagerKeyStoreParams = params;
    return this;
  }

  public WebIdSSLEngineBuilder setDefaultAlias(String defaultAlias) {
    this.defaultAlias = defaultAlias;
    return this;
  }

  public SSLEngine build() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, KeyManagementException {
    if (keyManagerKeyStoreBuilders == null) {
      throw new IllegalStateException("The key manager factory must be configured before building the SSLEngine.");

    } else if ((trustManagerKeyStore == null) && (trustManagerKeyStoreParams == null)) {
      throw new IllegalStateException("The trust manager factory must be configured before building the SSLEngine.");
    }

    final WebIdTrustManagerFactory tmf = new WebIdTrustManagerFactory();

    if (trustManagerKeyStore != null) {
      tmf.engineInit(trustManagerKeyStore);
    }

    if (trustManagerKeyStoreParams != null) {
      tmf.engineInit(trustManagerKeyStoreParams);
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
    sslContext.init(new KeyManager[] { keyManager }, tmf.engineGetTrustManagers(), null);

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
