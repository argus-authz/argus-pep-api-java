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
 * 
 * $Id$
 */
package org.glite.authz.pep.client.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

/**
 * PEM files reader to extract PEM encoded private key and certificates from
 * file. (OpenSSL compatible)
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEMFileReader {

    /** logger */
    private Log log= LogFactory.getLog(PEMFileReader.class);

    static {
        // add BouncyCastle security provider if not already done
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Default constructor.
     */
    public PEMFileReader() {
    }

    /**
     * 
     * @param filename
     * @param password
     * @return
     * @throws FileNotFoundException
     * @throws IOException
     */
    public PrivateKey readPrivateKey(String filename, String password)
            throws FileNotFoundException, IOException {
        File file= new File(filename);
        return readPrivateKey(file, password);
    }

    /**
     * 
     * @param file
     * @param password
     * @return
     * @throws FileNotFoundException
     * @throws IOException
     */
    public PrivateKey readPrivateKey(File file, String password)
            throws FileNotFoundException, IOException {
        log.debug("file: " + file);
        FileReader fileReader= new FileReader(file);
        PEMReader reader= new PEMReader(fileReader, new PEMPassword(password));
        KeyPair keyPair;
        Object object= null;
        do {
            object= reader.readObject();
            if (object == null) {
                log.error("No KeyPair object found in file " + file);
                throw new IOException("No KeyPair object found in file " + file);
            }
        } while (!(object instanceof KeyPair));

        try {
            reader.close();
        } catch (Exception e) {
            // ignored
        }

        keyPair= (KeyPair) object;
        return keyPair.getPrivate();
    }

    /**
     * 
     * @param filename
     * @param password
     * @return
     * @throws FileNotFoundException
     * @throws IOException
     */
    public X509Certificate[] readCertificates(String filename)
            throws FileNotFoundException, IOException {
        File file= new File(filename);
        return readCertificates(file);
    }

    /**
     * 
     * @param file
     * @param password
     * @return
     * @throws IOException
     */
    public X509Certificate[] readCertificates(File file)
            throws FileNotFoundException, IOException {
        FileReader fileReader= new FileReader(file);
        PEMReader reader= new PEMReader(fileReader, new PEMPassword());
        List<X509Certificate> certs= new ArrayList<X509Certificate>();
        Object object= null;
        do {
            try {
                // object is null at EOF
                object= reader.readObject();
                if (object instanceof X509CertificateObject) {
                    X509Certificate cert= (X509Certificate) object;
                    certs.add(cert);
                }
            } catch (IOException e) {
                // ignored, trying to read an encrypted object in file, like a
                // encrypted private key.
            }
        } while (object != null);

        try {
            reader.close();
        } catch (Exception e) {
            // ignored
        }

        return certs.toArray(new X509Certificate[] {});
    }

    /**
     * PEMPassword is a {@link PasswordFinder} for PEM encoded encrypted private
     * key or other object.
     */
    private class PEMPassword implements PasswordFinder {

        /** The password */
        private char[] password_= null;

        /**
         * Default constructor. The password is <code>null</code>.
         */
        public PEMPassword() {
            password_= null;
        }

        /**
         * Constructor.
         * 
         * @param password
         *            the PEM password.
         */
        public PEMPassword(String password) {
            if (password == null) {
                password_= null;
            }
            else {
                password_= password.toCharArray();
            }
        }

        /*
         * (non-Javadoc)
         * 
         * @see org.bouncycastle.openssl.PasswordFinder#getPassword()
         */
        public char[] getPassword() {
            return password_;
        }

    }
}
