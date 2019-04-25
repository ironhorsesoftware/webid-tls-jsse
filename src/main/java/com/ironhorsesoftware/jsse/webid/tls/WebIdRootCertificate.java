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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * An instance of this class is returned by {@link WebIdTrustManager#getAcceptedIssuers()}
 * for use when requesting certificates from the client, to ensure they are WebID certificates.
 *
 * Only the {@link #getSubjectDN()} method is needed for this purpose; the remainder of the
 * class is unimplemented and the remaining methods throw {@link UnsupportedOperationException}s.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 * @see WebIdTrustManager#getAcceptedIssuers()
 */
final class WebIdRootCertificate extends X509Certificate {

  /**
   * Returns the Web ID Issuer.
   *
   * @return {@link Constants#WEBID_ISSUER}.
   * @see java.security.cert.X509Certificate#getIssuerDN()
   */
  @Override
  public Principal getIssuerDN() {
    return Constants.WEBID_ISSUER;
  }

  /**
   * Returns the Web ID Issuer.
   *
   * @return {@link Constants#WEBID_ISSUER}.
   * @see java.security.cert.X509Certificate#getSubjectDN()
   */
  @Override
  public Principal getSubjectDN() {
    return Constants.WEBID_ISSUER;
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Extension#hasUnsupportedCriticalExtension()
   */
  @Override
  public boolean hasUnsupportedCriticalExtension() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Extension#getCriticalExtensionOIDs()
   */
  @Override
  public Set<String> getCriticalExtensionOIDs() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Extension#getNonCriticalExtensionOIDs()
   */
  @Override
  public Set<String> getNonCriticalExtensionOIDs() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Extension#getExtensionValue(java.lang.String)
   */
  @Override
  public byte[] getExtensionValue(String oid) {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#checkValidity()
   */
  @Override
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#checkValidity(java.util.Date)
   */
  @Override
  public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getVersion()
   */
  @Override
  public int getVersion() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSerialNumber()
   */
  @Override
  public BigInteger getSerialNumber() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getNotBefore()
   */
  @Override
  public Date getNotBefore() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getNotAfter()
   */
  @Override
  public Date getNotAfter() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getTBSCertificate()
   */
  @Override
  public byte[] getTBSCertificate() throws CertificateEncodingException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSignature()
   */
  @Override
  public byte[] getSignature() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSigAlgName()
   */
  @Override
  public String getSigAlgName() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSigAlgOID()
   */
  @Override
  public String getSigAlgOID() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSigAlgParams()
   */
  @Override
  public byte[] getSigAlgParams() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getIssuerUniqueID()
   */
  @Override
  public boolean[] getIssuerUniqueID() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getSubjectUniqueID()
   */
  @Override
  public boolean[] getSubjectUniqueID() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getKeyUsage()
   */
  @Override
  public boolean[] getKeyUsage() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.X509Certificate#getBasicConstraints()
   */
  @Override
  public int getBasicConstraints() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.Certificate#getEncoded()
   */
  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.Certificate#verify(java.security.PublicKey)
   */
  @Override
  public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchProviderException, SignatureException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.Certificate#verify(java.security.PublicKey, java.lang.String)
   */
  @Override
  public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
      InvalidKeyException, NoSuchProviderException, SignatureException {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.Certificate#toString()
   */
  @Override
  public String toString() {
    throw new UnsupportedOperationException();
  }

  /**
   * Throws an {@link UnsupportedOperationException} as this is not implemented.
   *
   * @see java.security.cert.Certificate#getPublicKey()
   */
  @Override
  public PublicKey getPublicKey() {
    throw new UnsupportedOperationException();
  }

}
