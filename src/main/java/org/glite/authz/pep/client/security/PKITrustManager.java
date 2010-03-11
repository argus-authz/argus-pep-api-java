/*
 * Copyright (c) 2010. Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * PKITrustManager is a {@link X509TrustManager} to manage which X509
 * certificates may be used to authenticate the remote side of a secure socket.
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 */
public class PKITrustManager implements X509TrustManager {

    /** Delegate */
    private X509TrustManager trustManager_= null;

    /**
     * 
     * @param keystore
     * @param password
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public PKITrustManager(KeyStore keystore) throws NoSuchAlgorithmException,
            KeyStoreException {
        trustManager_= createX509TrustManager(keystore);
    }

    /**
     * 
     * @param keystore
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    protected X509TrustManager createX509TrustManager(KeyStore keystore)
            throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmfactory= TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmfactory.init(keystore);
        X509TrustManager trustManager= (X509TrustManager) tmfactory.getTrustManagers()[0];
        return trustManager;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.
     * X509Certificate[], java.lang.String)
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        trustManager_.checkClientTrusted(chain, authType);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.
     * X509Certificate[], java.lang.String)
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        trustManager_.checkServerTrusted(chain, authType);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager_.getAcceptedIssuers();
    }

}
