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
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.glite.authz.pep.client.security.PKIKeyManager;
import org.glite.authz.pep.obligation.ObligationHandler;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.voms.PKIStore;
import org.glite.voms.VOMSTrustManager;

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
     * HTTP connection timeout in millis, <code>0</code> is no timeout. Default
     * is <code>5000</code> millis
     */
    private int connectionTimeout_= 5000;

    /** Default constructor. */
    public PEPClientConfiguration() {
        pepdEndpoints_= new ArrayList<String>();
        pips_= new ArrayList<PolicyInformationPoint>();
        obligationHandlers_= new ArrayList<ObligationHandler>();
    }

    /**
     * Gets an immutable list of PEP daemon endpoints.
     * 
     * @return unmodifiable list of PEP daemon endpoints
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
     * @return unmodifiable list of policy information points meant to be
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
     * @return unmodifiable list of obligation handlers used to process response
     *         obligations
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
     * @return the connection timeout in millis
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
     * 
     * @param cadirname
     * @throws CertificateException
     * @throws CRLException
     * @throws IOException
     */
    public void setTrustMaterial(String cadirname) throws CertificateException,
            CRLException, IOException {
        PKIStore trustStore= new PKIStore(cadirname, PKIStore.TYPE_CADIR);
        trustManager_= new VOMSTrustManager(trustStore);
    }

    /**
     * 
     * @param usercert
     * @param userkey
     * @param password
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void setKeyMaterial(String usercert, String userkey, String password)
            throws GeneralSecurityException, IOException {
        if (log_.isDebugEnabled()) {
            log_.debug("usercert: " + usercert);
            log_.debug("userkey: " + userkey + " password: " + password);
        }
        keyManager_= new PKIKeyManager(usercert, userkey, password);
    }

    /**
     * 
     * @param keystore
     * @param password
     * @throws GeneralSecurityException
     */
    public void setKeyMaterial(KeyStore keystore, String password)
            throws GeneralSecurityException {
        keyManager_= new PKIKeyManager(keystore, password);
    }

    /**
     * @return the {@link X509TrustManager} or <code>null</code> if no trust
     *         material have been defined
     */
    public X509TrustManager getTrustManager() {
        return trustManager_;
    }

    /**
     * @return the {@link X509KeyManager} or <code>null</code> if no key
     *         material have been defined
     */
    public X509KeyManager getKeyManager() {
        return keyManager_;
    }
}