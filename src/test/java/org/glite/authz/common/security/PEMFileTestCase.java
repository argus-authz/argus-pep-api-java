/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.glite.authz.common.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

/**
 * JUnit to test {@link PEMFileReader} with PKCS1, PKCS8 and invalid private
 * keys.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEMFileTestCase extends TestCase {

  String keyFilename = "key.pem";
  String pkcs8keyFilename = "key_pkcs8.pem";
  String invalidKeyFilename = "key_invalid.pem";
  String proxyFilename = "x509up_u1000";
  String password = "test";
  String proxyPasswd = "pass";

  @Override
  protected void setUp() throws Exception {

    super.setUp();
    System.out.println("--------" + this.getName() + "------------");
  }

  public void testPEMFileReaderReadPrivateKey() throws IOException {

    InputStream keyInputStream = getClass()
      .getResourceAsStream("/" + keyFilename);
    assertNotNull("InputStream " + keyFilename + " not found", keyInputStream);
    PEMFileReader pfr = new PEMFileReader();
    PrivateKey pkey = pfr.readPrivateKey(keyInputStream, password);
    assertNotNull(pkey);
    System.out.println("class: " + pkey.getClass().getName());
    System.out.println("format: " + pkey.getFormat());
    System.out.println("algorithm: " + pkey.getAlgorithm());
  }

  public void testPKCS8PEMFileReaderReadPrivateKey() throws IOException {

    InputStream keyInputStream = getClass()
      .getResourceAsStream("/" + pkcs8keyFilename);
    assertNotNull("InputStream " + pkcs8keyFilename + " not found",
      keyInputStream);
    PEMFileReader pfr = new PEMFileReader();
    PrivateKey pkey = pfr.readPrivateKey(keyInputStream, password);
    assertNotNull(pkey);
    System.out.println("class: " + pkey.getClass().getName());
    System.out.println("format: " + pkey.getFormat());
    System.out.println("algorithm: " + pkey.getAlgorithm());

  }

  public void testInvalidPEMFileReaderReadPrivateKey() {

    InputStream keyInputStream = getClass()
      .getResourceAsStream("/" + invalidKeyFilename);
    assertNotNull("InputStream " + invalidKeyFilename + " not found",
      keyInputStream);
    PEMFileReader pfr = new PEMFileReader();
    try {
      PrivateKey pkey = pfr.readPrivateKey(keyInputStream, null);
      pkey.getAlgorithm();
    } catch (IOException e) {
      // expected :)
      System.out.println("Expected IOException: " + e);
    }

  }

  public void testPEMFileReaderReadProxy() throws Exception {

    String filePath = getClass().getResource("/" + proxyFilename).getPath();
    PEMFileReader pfr = new PEMFileReader();
    X509Certificate[] proxy = pfr.readProxyCertificate(filePath, proxyPasswd);

    assertNotNull(proxy);

  }

}
