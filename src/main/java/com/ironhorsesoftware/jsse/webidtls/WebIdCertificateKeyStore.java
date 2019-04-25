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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;

/**
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 *
 */
public final class WebIdCertificateKeyStore extends KeyStoreSpi {

  /**
   * 
   * @see java.security.KeyStoreSpi#engineGetKey(java.lang.String, char[])
   */
  @Override
  public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineGetCertificateChain(java.lang.String)
   */
  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineGetCertificate(java.lang.String)
   */
  @Override
  public Certificate engineGetCertificate(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineGetCreationDate(java.lang.String)
   */
  @Override
  public Date engineGetCreationDate(String alias) {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, java.security.Key, char[], java.security.cert.Certificate[])
   */
  @Override
  public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineSetKeyEntry(java.lang.String, byte[], java.security.cert.Certificate[])
   */
  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineSetCertificateEntry(java.lang.String, java.security.cert.Certificate)
   */
  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineDeleteEntry(java.lang.String)
   */
  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineAliases()
   */
  @Override
  public Enumeration<String> engineAliases() {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineContainsAlias(java.lang.String)
   */
  @Override
  public boolean engineContainsAlias(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineSize()
   */
  @Override
  public int engineSize() {
    // TODO Auto-generated method stub
    return 0;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineIsKeyEntry(java.lang.String)
   */
  @Override
  public boolean engineIsKeyEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineIsCertificateEntry(java.lang.String)
   */
  @Override
  public boolean engineIsCertificateEntry(String alias) {
    // TODO Auto-generated method stub
    return false;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineGetCertificateAlias(java.security.cert.Certificate)
   */
  @Override
  public String engineGetCertificateAlias(Certificate cert) {
    // TODO Auto-generated method stub
    return null;
  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineStore(java.io.OutputStream, char[])
   */
  @Override
  public void engineStore(OutputStream stream, char[] password)
      throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub

  }

  /**
   * 
   * @see java.security.KeyStoreSpi#engineLoad(java.io.InputStream, char[])
   */
  @Override
  public void engineLoad(InputStream stream, char[] password)
      throws IOException, NoSuchAlgorithmException, CertificateException {
    // TODO Auto-generated method stub

  }

}
