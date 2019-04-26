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

import javax.security.auth.x500.X500Principal;

/**
 * Constants available for reuse.
 *
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class Constants {

  /**
   * This represents the X.500 distinguished name for the issuer of WebID self-signed certificates.
   */
  public static final X500Principal WEBID_ISSUER = new X500Principal("O={}, CN=WebID");

  public static final String SIGNATURE_ALGORITHM_SHA512withRSA = "SHA512withRSA";

  public static final long ONE_HOUR_IN_MILLIS = 60L * 60L * 1000L;

  public static final long ONE_DAY_IN_MILLIS = 24L * ONE_HOUR_IN_MILLIS;

  /**
   *  Approximating 365.25 days in a year.
   */
  public static final double APPROX_DAYS_IN_YEAR = 365.25;

  /**
   *  7305 days in 20 years, approximating 365.25 days per year.
   */
  public static final long TWENTY_YEARS_IN_MILLIS = 7305L * 24L * 60L * 60L * 1000L;
}
