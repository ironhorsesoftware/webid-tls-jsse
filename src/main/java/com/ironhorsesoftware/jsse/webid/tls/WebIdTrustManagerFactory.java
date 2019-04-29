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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * The <code>TrustManagerFactory</code> constructs {@link WebIdTrustManager}s.
 * 
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public class WebIdTrustManagerFactory extends TrustManagerFactorySpi {

  private List<KeyStore> validatedCertificateStores;

  public WebIdTrustManagerFactory() {
    this.validatedCertificateStores = null;
  }

  /**
   * Constructs a single {@link WebIdTrustManager} and returns it in the array.
   * @see javax.net.ssl.TrustManagerFactorySpi#engineGetTrustManagers()
   */
  @Override
  public TrustManager[] engineGetTrustManagers() {
    return new TrustManager[]{ new WebIdTrustManager(validatedCertificateStores, true) };
  }

  /**
   * Adds the provided {@link KeyStore} to the set of key stores the {@link WebIdTrustManager}
   * will use when verifying certificates.  If a previously-unrecognized certificate is verified
   * by the trust manager, it will be added to this {@link KeyStore}.
   *
   * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(java.security.KeyStore)
   */
  @Override
  public void engineInit(KeyStore keyStore) throws KeyStoreException {
    if (keyStore == null) {
      throw new KeyStoreException("The KeyStore must not be null.");
    }

    if (this.validatedCertificateStores == null) {
      this.validatedCertificateStores = new ArrayList<>();
    }

    this.validatedCertificateStores.add(keyStore);
  }

  /**
   * Given a set of {@link KeyStoreBuilderParameters}, constructs the corresponding {@link KeyStore}s
   * and adds them to the set of key stores the {@link WebIdTrustManager} will use when verifying
   * certificates.  If a previously-unrecognized certificate is verified by the trust manager, it
   * will be added to all {@link KeyStore}s built.
   *
   * @throws InvalidAlgorithmParameterException if the ManagerFactoryParameters is either null or not
   *                                            an instance of KeyStoreBuilderParameters, or if a
   *                                            KeyStore cannot be constructed.
   * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(javax.net.ssl.ManagerFactoryParameters)
   */
  @Override
  public void engineInit(ManagerFactoryParameters mfp) throws InvalidAlgorithmParameterException {
    if (mfp == null) {
      throw new InvalidAlgorithmParameterException("Manager Factory Parameters cannot be null.");

    } else if (!(mfp instanceof KeyStoreBuilderParameters)) {
      throw new InvalidAlgorithmParameterException("WEBID-TLS TrustManager only supports KeyStoreBuilderParameters.");
    }

    if (this.validatedCertificateStores == null) {
      this.validatedCertificateStores = new ArrayList<>();
    }

    final List<KeyStore.Builder> builders = ((KeyStoreBuilderParameters) mfp).getParameters();

    for (KeyStore.Builder builder : builders) {
      try {
        this.validatedCertificateStores.add(builder.getKeyStore());
      } catch (KeyStoreException e) {
        throw new InvalidAlgorithmParameterException("Cannot construct all KeyStores.", e);
      }
    }
  }
}
