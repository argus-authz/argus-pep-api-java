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
package org.glite.authz.pep.client.config;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.glite.authz.common.security.PKIKeyManager;
import org.glite.authz.common.security.PKITrustManager;
import org.glite.authz.pep.obligation.ObligationHandler;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.voms.PKIStore;
import org.glite.voms.VOMSTrustManager;

import org.apache.commons.httpclient.params.HttpConnectionManagerParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * PEP client configuration
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEPClientConfiguration {

    /** Logging */
    private Log log_= LogFactory.getLog(PEPClientConfiguration.class);

    /** Registered PEP daemon endpoints. */
    private List<String> pepdEndpoints_;

    /** Registered {@link PolicyInformationPoint}s. */
    private List<PolicyInformationPoint> pips_;

    /** Obligation processing service. */
    private List<ObligationHandler> obligationHandlers_;

    /** HTTPS trust manager */
    private X509TrustManager trustManager_= null;

    /** HTTPS client authentication key manager */
    private X509KeyManager keyManager_= null;

    /**
     * HTTP connection timeout in millis, <code>0</code> is no timeout.
     */
    private int connectionTimeout_= 5000;

    /** Max connections per host for the multi-threaded Http client */
    private int maxConnectionsPerHost_= 5;

    /** Max total number of connections for the multi-threaded Http client */
    private int maxTotalConnections_= 20;

    /** Default constructor. */
    public PEPClientConfiguration() {
        pepdEndpoints_= new ArrayList<String>();
        pips_= new ArrayList<PolicyInformationPoint>();
        obligationHandlers_= new ArrayList<ObligationHandler>();
    }

    /**
     * Gets an unmodifiable list of PEP daemon endpoints.
     * 
     * @return an unmodifiable list of PEP daemon endpoints
     */
    public List<String> getPEPDaemonEndpoints() {
        return Collections.unmodifiableList(pepdEndpoints_);
    }

    /**
     * Adds a PEP daemon endpoint URL
     * 
     * @param endpoint
     *            PEP daemon endpoint url to add
     */
    public void addPEPDaemonEndpoint(String endpoint) {
        pepdEndpoints_.add(endpoint);
    }

    /**
     * Gets the policy information points meant to be applied to each request.
     * 
     * @return an unmodifiable list of policy information points meant to be
     *         applied to each request
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
        return Collections.unmodifiableList(pips_);
    }

    /**
     * Adds a {@link PolicyInformationPoint} to the list of PIP to be applied to
     * each request.
     * 
     * @param pip
     *            policy information point to add
     */
    public void addPolicyInformationPoint(PolicyInformationPoint pip) {
        pips_.add(pip);
    }

    /**
     * Gets the obligation handlers used to process response obligations.
     * 
     * @return an unmodifiable list of obligation handlers used to process
     *         response obligations
     */
    public List<ObligationHandler> getObligationHandlers() {
        return Collections.unmodifiableList(obligationHandlers_);
    }

    /**
     * Adds an {@link ObligationHandler} to the list of OHs used to process
     * response obligations.
     * 
     * @param oh
     *            obligation handler to add
     */
    public void addObligationHandler(ObligationHandler oh) {
        obligationHandlers_.add(oh);
    }

    /**
     * Returns the HTTP connection timeout in millisecond. Default is
     * <code>5000</code> milliseconds.
     * 
     * @return the connection timeout
     */
    public int getConnectionTimeout() {
        return connectionTimeout_;
    }

    /**
     * Sets the HTTP connection timeout in millis. <code>0</code> for no
     * timeout.
     * 
     * @param timeout
     *            HTTP connection timeout in millis
     */
    public void setConnectionTimeout(int timeout) {
        connectionTimeout_= timeout;
    }

    /**
     * Sets the directory containing the trust material X509 certificates used
     * to authenticate the server side of a secure socket (server
     * authentication). This is typically the EUGridPMA bundle directory
     * <code>/etc/grid-security/certificates</code>
     * 
     * @param cadirname
     *            the directory containing the CA issuing certificates in PEM
     *            format. This is typically the EUGridPMA bundle directory
     *            <code>/etc/grid-security/certificates</code>
     * @throws PEPClientConfigurationError
     *             if an error occurs processing the cadirname or creating the
     *             trust manager
     */
    public void setTrustMaterial(String cadirname)
            throws PEPClientConfigurationError {
        if (log_.isDebugEnabled()) {
            log_.debug("cadirname: " + cadirname);
        }
        try {
            PKIStore trustStore= new PKIStore(cadirname, PKIStore.TYPE_CADIR);
            trustManager_= new VOMSTrustManager(trustStore);
        } catch (CertificateException e) {
            throw new PEPClientConfigurationError(e);
        } catch (CRLException e) {
            throw new PEPClientConfigurationError(e);
        } catch (IOException e) {
            throw new PEPClientConfigurationError(e);
        }
    }

    /**
     * Sets the trust material X509 certificates used to authenticate the server
     * side of a secure socket (server authentication).
     * 
     * @param truststore
     *            the trust store containing the trusted server certificates or
     *            issuing CA certificates.
     * @throws PEPClientConfigurationError
     *             if an error occurs creating the trust manager
     */
    public void setTrustMaterial(KeyStore truststore)
            throws PEPClientConfigurationError {
        try {
            trustManager_= new PKITrustManager(truststore);
        } catch (NoSuchAlgorithmException e) {
            throw new PEPClientConfigurationError(e);
        } catch (KeyStoreException e) {
            throw new PEPClientConfigurationError(e);
        }
    }

    /**
     * Sets the key material X509 certificate-based key pairs used to
     * authenticate the client side of a secure socket (client authentication).
     * The certificate and private key must be in PEM format.
     * 
     * @param usercert
     *            the filename containing the X509 certificate in PEM format
     * @param userkey
     *            the filename containing the private key in PEM format
     * @param password
     *            the password of the private key, and of the resulting
     *            keystore. It can not be <code>null</code>.
     * @throws PEPClientConfigurationError
     *             if an error occurs reading the key material or creating the
     *             key manager
     */
    public void setKeyMaterial(String usercert, String userkey, String password)
            throws PEPClientConfigurationError {
        if (password == null) {
            throw new IllegalArgumentException("password can not be null");
        }
        if (log_.isDebugEnabled()) {
            log_.debug("usercert: " + usercert);
            log_.debug("userkey: " + userkey + " password: " + password);
        }
        try {
            keyManager_= new PKIKeyManager(usercert, userkey, password);
        } catch (GeneralSecurityException e) {
            throw new PEPClientConfigurationError(e);
        } catch (IOException e) {
            throw new PEPClientConfigurationError(e);
        }
    }

    /**
     * Sets the key material X509 certificate-based key pairs used to
     * authenticate the client side of a secure socket (client authentication).
     * 
     * @param keystore
     *            the KeyStore containing the certificate-based key pairs
     * @param password
     *            password of the keystore, can not be <code>null</code>
     * @throws PEPClientConfigurationError
     *             if an error occurs reading the key material or creating the
     *             key manager
     */
    public void setKeyMaterial(KeyStore keystore, String password)
            throws PEPClientConfigurationError {
        if (password == null) {
            throw new IllegalArgumentException("password can not be null");
        }
        try {
            keyManager_= new PKIKeyManager(keystore, password);
        } catch (GeneralSecurityException e) {
            throw new PEPClientConfigurationError(e);
        }
    }

    /**
     * Gets the trust manager if any
     * 
     * @return the {@link X509TrustManager} or <code>null</code> if no trust
     *         material have been defined
     */
    public X509TrustManager getTrustManager() {
        return trustManager_;
    }

    /**
     * Gets the key manager if any
     * 
     * @return the {@link X509KeyManager} or <code>null</code> if no key
     *         material have been defined
     */
    public X509KeyManager getKeyManager() {
        return keyManager_;
    }

    /**
     * Gets the maximum number of connections per host to keep alive. Default is
     * <code>5</code>.
     * 
     * @return maximum number of connection per host
     */
    public int getMaxConnectionsPerHost() {
        return maxConnectionsPerHost_;
    }

    /**
     * Sets the maximum number of connections per host to keep alive.
     * 
     * @param connectionsPerHost
     *            maximum number of connections per host
     * @see HttpConnectionManagerParams#setDefaultMaxConnectionsPerHost(int)
     */
    public void setMaxConnectionsPerHost(int connectionsPerHost) {
        maxConnectionsPerHost_= connectionsPerHost;
    }

    /**
     * Sets the maximum total number of connections in the connections pool to
     * keep alive.
     * 
     * @param maxConnections
     *            maximum total number of connections
     * @see HttpConnectionManagerParams#setMaxTotalConnections(int)
     */
    public void setMaxTotalConnections(int maxConnections) {
        maxTotalConnections_= maxConnections;
    }

    /**
     * Gets the maximum total number of connections in the connections pool.
     * Default is <code>20</code>.
     * 
     * @return maximum total number of connections
     */
    public int getMaxTotalConnections() {
        return maxTotalConnections_;
    }
}