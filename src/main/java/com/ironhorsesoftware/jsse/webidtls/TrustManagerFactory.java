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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * The <code>TrustManagerFactory</code> constructs {@link WebIdTrustManager}s.
 * 
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class TrustManagerFactory extends TrustManagerFactorySpi {

  private WebIdTrustManager trustManager;

  public TrustManagerFactory() {
    trustManager = new WebIdTrustManager();
  }

  /**
   * 
   * @see javax.net.ssl.TrustManagerFactorySpi#engineGetTrustManagers()
   */
  @Override
  protected TrustManager[] engineGetTrustManagers() {
    return new TrustManager[]{ trustManager };
  }

  /**
   * 
   * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(java.security.KeyStore)
   */
  @Override
  protected void engineInit(KeyStore keyStore) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(javax.net.ssl.ManagerFactoryParameters)
   */
  @Override
  protected void engineInit(ManagerFactoryParameters mfp) throws InvalidAlgorithmParameterException {
    // TODO Auto-generated method stub

  }

}
