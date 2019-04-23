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

/**
 * This class is a provider of WebID-TLS and SPI for the Java Secure Socket Extension.
 * 
 * @author Mike Pigott (mpigott@ironhorsesoftware.com)
 */
public final class Provider extends java.security.Provider {

  private static final long serialVersionUID = 4177247835096695438L;

  /**
   * Instantiates a new Provider for use with the JSSE libraries.
   */
  public Provider() {
    super("IronHorseSoftware", 0.1, "WebID-TLS Provider");
  }
}
