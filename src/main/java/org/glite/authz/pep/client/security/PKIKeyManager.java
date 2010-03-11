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

import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * PKIKeyManager is a {@link X509KeyManager} to manage which X509
 * certificate-based key pairs is used to authenticate the local side of a
 * secure socket.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PKIKeyManager implements X509KeyManager {

    /** Delegate */
    private X509KeyManager keyManager_= null;

    /**
     * Constructor where the key material is contained in PEM encoded
     * certificate and private key files. (OpenSSL compatible)
     * 
     * @param certfile
     *            PEM encoded certificate(s) filename
     * @param keyfile
     *            PEM encoded private key filename
     * @param password
     *            private key and keystore password, can not be
     *            <code>null</code>
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws CertificateException
     */
    public PKIKeyManager(String certfile, String keyfile, String password)
            throws IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, CertificateException {
        KeyStore keystore= createKeyStore(certfile, keyfile, password);
        keyManager_= createX509KeyManager(keystore, password);
    }

    /**
     * Constructor based on a {@link KeyStore} containing the certificate and
     * the private key.
     * 
     * @param keystore
     *            the keystore containing the certificate and private key
     * @param password
     *            the keystore password
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public PKIKeyManager(KeyStore keystore, String password)
            throws UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        keyManager_= createX509KeyManager(keystore, password);
    }

    /**
     * Creates and initializes a {@link KeyStore} with key material from PEM
     * encoded files.
     * 
     * @param certfile
     *            PEM encoded certificate filename
     * @param keyfile
     *            PEM encoded private key filename
     * @param password
     *            password for the encrypted private key and the resulting
     *            keystore, can not be <code>null</code>
     * @return the KeyStore containing the key material
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    protected KeyStore createKeyStore(String certfile, String keyfile,
            String password) throws IOException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException {
        PEMFileReader reader= new PEMFileReader();
        PrivateKey pkey= reader.readPrivateKey(keyfile, password);
        X509Certificate[] certs= reader.readCertificates(certfile);
        char passwd[]= password.toCharArray();
        KeyStore keystore= KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, passwd);
        keystore.setKeyEntry("keycreds", pkey, passwd, certs);
        return keystore;
    }

    /**
     * 
     * @param keystore
     * @param password
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     */
    protected X509KeyManager createX509KeyManager(KeyStore keystore,
            String password) throws NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyStoreException {
        KeyManagerFactory kmfactory= KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmfactory.init(keystore, password.toCharArray());
        X509KeyManager keyManager= (X509KeyManager) kmfactory.getKeyManagers()[0];
        return keyManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[],
     * java.security.Principal[], java.net.Socket)
     */
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket) {
        return keyManager_.chooseClientAlias(keyType, issuers, socket);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String,
     * java.security.Principal[], java.net.Socket)
     */
    public String chooseServerAlias(String keyType, Principal[] issuers,
            Socket socket) {
        return keyManager_.chooseServerAlias(keyType, issuers, socket);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
     */
    public X509Certificate[] getCertificateChain(String alias) {
        return keyManager_.getCertificateChain(alias);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String,
     * java.security.Principal[])
     */
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return keyManager_.getClientAliases(keyType, issuers);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
     */
    public PrivateKey getPrivateKey(String alias) {
        return keyManager_.getPrivateKey(alias);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String,
     * java.security.Principal[])
     */
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return keyManager_.getServerAliases(keyType, issuers);
    }

}
