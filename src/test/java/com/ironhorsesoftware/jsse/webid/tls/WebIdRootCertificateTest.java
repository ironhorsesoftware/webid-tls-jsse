package com.ironhorsesoftware.jsse.webid.tls;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import com.ironhorsesoftware.jsse.webid.Constants;

public class WebIdRootCertificateTest {

  private WebIdRootCertificate webIdCert;

  @Before
  public void setUp() throws Exception {
    webIdCert = new WebIdRootCertificate();
  }

  @Test
  public void testIssuer() {
    assertEquals(Constants.WEBID_ISSUER, webIdCert.getIssuerDN());
    assertEquals(Constants.WEBID_ISSUER, webIdCert.getIssuerX500Principal());
  }

  @Test
  public void testSubject() {
    assertEquals(Constants.WEBID_ISSUER, webIdCert.getSubjectDN());
    assertEquals(Constants.WEBID_ISSUER, webIdCert.getSubjectX500Principal());
  }
}
