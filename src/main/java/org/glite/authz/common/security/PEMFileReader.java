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
package org.glite.authz.common.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
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
import org.glite.authz.common.model.util.Strings;

/**
 * PEM files reader to extract PEM encoded private key and certificates from
 * file.
 * <p>
 * <ul>
 * <li>OpenSSL 0.9 PCKS1 format compatible
 * <li>OpenSSL 1.0 PKCS8 format compatible (requires BouncyCastle >= 1.46)
 * </ul>
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
     * Reads the <b>first</b> available PEM encoded private key (PKCS1 and PKCS8
     * format) from a filename.
     * 
     * @param filename
     *            the filename of the file to read from
     * @param password
     *            the password of the private key if encrypted, can be
     *            <code>null</code> if the key is not encrypted
     * @return the private key
     * @throws FileNotFoundException
     *             if the file doesn't exist
     * @throws IOException
     *             if an error occurs while reading the file
     */
    public PrivateKey readPrivateKey(String filename, String password)
            throws FileNotFoundException, IOException {
        File file= new File(filename);
        return readPrivateKey(file, password);
    }

    /**
     * Reads the <b>first</b> available PEM encoded private key (PKCS1 and PKCS8
     * format) from a file object.
     * 
     * @param file
     *            the file to read from
     * @param password
     *            the password of the private key if encrypted, can be
     *            <code>null</code> if the key is not encrypted
     * @return the private key
     * @throws FileNotFoundException
     *             if the file doesn't exist
     * @throws IOException
     *             if an error occurs while reading the file
     */
    public PrivateKey readPrivateKey(File file, String password)
            throws FileNotFoundException, IOException {
        log.debug("file: " + file);
        InputStream is= new FileInputStream(file);
        try {
            return readPrivateKey(is, password);
        } catch (IOException ioe) {
            String error= "Invalid file " + file + ": " + ioe.getMessage();
            log.error(error);
            throw new IOException(error, ioe);
        }
    }

    /**
     * Reads the <b>first</b> available PEM encoded private key (PKCS1 and PKCS8
     * format) from an input stream.
     * 
     * @param is
     *            the input stream
     * @param password
     *            the password of the private key if encrypted, can be
     *            <code>null</code> if the key is not encrypted
     * @return the private key
     * @throws IOException
     *             if an error occurs while parsing the input stream
     */
    protected PrivateKey readPrivateKey(InputStream is, String password)
            throws IOException {
        Reader inputStreamReader= new InputStreamReader(is);
        PEMReader reader= new PEMReader(inputStreamReader, new PEMPassword(password));
        KeyPair keyPair;
        Object object= null;
        do {
            object= reader.readObject();
            if (object == null) {
                String error= "No KeyPair or PrivateKey object found";
                log.error(error);
                throw new IOException(error);
            }
        } while (!(object instanceof KeyPair || object instanceof PrivateKey));

        log.debug("Object type: " + object.getClass().getCanonicalName());

        try {
            reader.close();
        } catch (Exception e) {
            // ignored
        }
        if (object instanceof KeyPair) {
            keyPair= (KeyPair) object;
            return keyPair.getPrivate();
        }
        else if (object instanceof PrivateKey) {
            return (PrivateKey) object;
        }
        else {
            String error= "Unknown object type: " + object.getClass().getName();
            log.error(error);
            throw new IOException(error);

        }
    }

    /**
     * Reads all PEM encoded X.509 certificates from a file
     * 
     * @param filename
     *            the filename of the file to read from
     * @return a list of all X.509 certificates
     * @throws IOException
     *             if an error occurs while reading the file
     */
    public X509Certificate[] readCertificates(String filename)
            throws FileNotFoundException, IOException {
        File file= new File(filename);
        return readCertificates(file);
    }

    /**
     * Reads all PEM encoded X.509 certificates from a file
     * 
     * @param file
     *            the file to read from
     * @return a list of all X.509 certificates
     * @throws IOException
     *             if an error occurs while reading the file
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
            else if (Strings.safeTrimOrNullString(password) == null) {
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
