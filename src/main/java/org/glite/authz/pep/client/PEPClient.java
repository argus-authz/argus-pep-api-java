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
package org.glite.authz.pep.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.util.Base64;
import org.glite.authz.pep.client.config.PEPClientConfiguration;
import org.glite.authz.pep.client.http.HttpClientBuilder;
import org.glite.authz.pep.client.http.TLSProtocolSocketFactory;
import org.glite.authz.pep.obligation.ObligationHandler;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

/**
 * A PEP client to communicate with the Argus PEP daemon and authorize request.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEPClient {

    /** Class logger. */
    private final Log log= LogFactory.getLog(PEPClient.class);

    private List<PolicyInformationPoint> pips_= null;

    private List<ObligationHandler> obligationHandlers_= null;

    private List<String> pepdEndpoints_= null;

    /** HTTP client used to contact the PEP daemon. */
    private HttpClient httpClient_= null;

    /**
     * Constructor.
     * 
     * @param config
     *            the client configuration used for this client
     */
    public PEPClient(PEPClientConfiguration config) {
        HttpClientBuilder httpClientBuilder= new HttpClientBuilder();
        httpClientBuilder.setConnectionTimeout(config.getConnectionTimeout());
        // httpClientBuilder.setMaxTotalConnections(config.getMaxRequests());
        // httpClientBuilder.setReceiveBufferSize(config.getReceiveBufferSize());
        // httpClientBuilder.setSendBufferSize(config.getSendBufferSize());

        if (config.getTrustManager() != null) {
            // it's okay if the key manager is null, it just means client-auth
            // isn't enabled
            httpClientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(config.getKeyManager(),
                                                                                         config.getTrustManager()));
        }
        httpClient_= httpClientBuilder.buildClient();

        pepdEndpoints_= config.getPEPDaemonEndpoints();
        pips_= config.getPolicyInformationPoints();
        obligationHandlers_= config.getObligationHandlers();
    }

    /**
     * 
     * @param request
     * @return
     * @throws AuthorizationServiceException
     */
    public Response authorize(Request request)
            throws AuthorizationServiceException {
        Response response= null;
        runPolicyInformationPoints(request);
        for (String endpoint : pepdEndpoints_) {
            try {
                response= performRequest(endpoint, request);
                // success, exit loop
                break;
            } catch (AuthorizationServiceException e) {
                log.warn("request failed for PEP daemon " + endpoint, e);
            }
        }
        if (response == null) {
            String error= "No PEP daemons " + pepdEndpoints_
                    + " was able to process the request";
            log.error(error);
            throw new AuthorizationServiceException(error);
        }
        runObligationHandlers(request, response);
        return response;
    }

    /**
     * Calls out to the remote PEP and returns the response.
     * 
     * @param pepUrl
     *            the remote PEP to which to callout
     * @param authzRequest
     *            the authorization request to send to the PEP daemon
     * 
     * @return the response to the request
     * 
     * @throws AuthorizationServiceException
     *             thrown if there is a problem processing the request
     */
    protected Response performRequest(String pepUrl, Request authzRequest)
            throws AuthorizationServiceException {
        PostMethod postMethod= null;

        try {
            ByteArrayOutputStream out= new ByteArrayOutputStream();
            HessianOutput hout= new HessianOutput(out);
            hout.writeObject(authzRequest);
            hout.flush();

            String b64Message= Base64.encodeBytes(out.toByteArray());
            if (log.isDebugEnabled()) {
                log.debug("Outgoing Base64-encoded request:\n" + b64Message);
            }

            postMethod= new PostMethod(pepUrl);
            postMethod.setRequestEntity(new StringRequestEntity(b64Message,
                                                                "UTF-8",
                                                                "UTF-8"));
        } catch (IOException e) {
            log.error("Unable to serialize request object", e);
            throw new AuthorizationServiceException("Unable to serialize request object",
                                                    e);
        }

        try {
            httpClient_.executeMethod(postMethod);
            if (postMethod.getStatusCode() == HttpStatus.SC_OK) {
                HessianInput hin= new HessianInput(new Base64.InputStream(postMethod.getResponseBodyAsStream()));
                return (Response) hin.readObject(Response.class);
            }
            else {
                String error= "Received a " + postMethod.getStatusCode()
                        + " status code response from the PEP daemon " + pepUrl;
                log.error(error);
                throw new AuthorizationServiceException(error);

            }
        } catch (IOException e) {
            log.error("Unable to read response from PEP daemon " + pepUrl, e);
            throw new AuthorizationServiceException("Unable to read response from PEP daemon "
                                                            + pepUrl,
                                                    e);
        } finally {
            postMethod.releaseConnection();
        }
    }

    /**
     * Run the list of PIPs over the request.
     * 
     * @param request
     *            the request
     * @param pips
     *            PIPs to run over the request
     * 
     * @throws AuthorizationServiceException
     *             thrown if there is a
     */
    protected void runPolicyInformationPoints(Request request)
            throws AuthorizationServiceException {

        boolean pipApplied;

        log.debug("Running " + pips_.size() + " registered PIPs");
        for (PolicyInformationPoint pip : pips_) {
            if (pip != null) {
                pipApplied= pip.populateRequest(request);
                if (pipApplied) {
                    log.debug("PIP " + pip.getId()
                            + " was applied to the request");
                }
                else {
                    log.debug("PIP " + pip.getId()
                            + " did not apply to the request");
                }
            }
        }
    }

    /**
     * Runs the obligations handlers over the returned response.
     * 
     * @param request
     *            the authorization request made
     * @param response
     *            the authorization response
     * 
     * @throws AuthorizationServiceException
     *             thrown if there is a problem evaluating obligation handlers.
     */
    protected void runObligationHandlers(Request request, Response response)
            throws AuthorizationServiceException {
        if (response == null)
            return;
        List<Result> results= response.getResults();
        for (Result result : results) {
            for (ObligationHandler oh : obligationHandlers_) {
                if (oh != null) {
                    log.debug("applying OH " + oh.getObligationId());
                    oh.evaluateObligation(request, result);
                }
            }
        }
    }

}