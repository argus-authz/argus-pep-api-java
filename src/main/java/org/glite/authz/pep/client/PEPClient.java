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
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.util.Base64;
import org.glite.authz.pep.client.config.PEPClientConfiguration;
import org.glite.authz.pep.client.http.HttpClientBuilder;
import org.glite.authz.pep.client.http.TLSProtocolSocketFactory;
import org.glite.authz.pep.obligation.ObligationHandler;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

/**
 * A PEP client to communicate with the Argus PEP Server and authorize request.
 * 
 * It uses a multi-threaded http client to authorize the request. The http
 * client tries to keep alive connection whitin its pool of connections.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEPClient {

    /** Class logger. */
    private final Log log= LogFactory.getLog(PEPClient.class);

    /** Unmodifiable list of PIPs */
    private List<PolicyInformationPoint> pips_= null;

    /** Unmodifiable list of ObligationHandlers */
    private List<ObligationHandler> obligationHandlers_= null;

    /** Unmodifiable list of PEP daemon endpoints */
    private List<String> pepdEndpoints_= null;

    /** HTTP client used to contact the PEP daemon. */
    private HttpClient httpClient_= null;

    /**
     * Constructor. Creates a new PEP client based on the given configuration.
     * The PEP client uses a multi-threaded {@link HttpClient} with a pool of
     * connections.
     * 
     * @param config
     *            the client configuration used for this client
     * @throws PEPClientException
     */
    public PEPClient(PEPClientConfiguration config) throws PEPClientException {
        HttpClientBuilder httpClientBuilder= new HttpClientBuilder();
        httpClientBuilder.setConnectionTimeout(config.getConnectionTimeout());
        httpClientBuilder.setMaxConnectionsPerHost(config.getMaxConnectionsPerHost());
        httpClientBuilder.setMaxTotalConnections(config.getMaxTotalConnections());
        // httpClientBuilder.setReceiveBufferSize(config.getReceiveBufferSize());
        // httpClientBuilder.setSendBufferSize(config.getSendBufferSize());

        if (config.getTrustManager() != null) {
            // if the key manager is null, it just means TLS client-auth isn't
            // enabled
            httpClientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(config.getKeyManager(),
                                                                                         config.getTrustManager()));
        }
        httpClient_= httpClientBuilder.buildClient();

        pepdEndpoints_= config.getPEPDaemonEndpoints();
        if (pepdEndpoints_.isEmpty()) {
            throw new PEPClientException("Configuration doesn't contain any PEP Server endpoint URL");
        }
        pips_= config.getPolicyInformationPoints();
        obligationHandlers_= config.getObligationHandlers();
    }

    /**
     * Authorizes the request with the PEP daemon and return the response
     * 
     * @param request
     *            the authorization request
     * @return the reponse
     * @throws PEPClientException
     *             if a processing error occurs.
     */
    public Response authorize(Request request) throws PEPClientException {
        Response response= null;
        Exception cause= null;
        try {
            runPolicyInformationPoints(request);
        } catch (PIPProcessingException e) {
            throw new PEPClientException("PIP processing failure", e);
        }
        for (String endpoint : pepdEndpoints_) {
            try {
                response= performRequest(endpoint, request);
                // success, exit loop
                break;
            } catch (PEPClientException e) {
                log.error("Request failed for PEP Server " + endpoint, e);
                cause= e;
            }
        }
        if (response == null) {
            String error= "No PEP Server " + pepdEndpoints_
                    + " was able to process the request";
            log.error(error);
            PEPClientException exception= new PEPClientException(error,cause);
            if (cause != null) {
                exception.setStackTrace(cause.getStackTrace());
            }
            throw exception;
        }
        try {
            runObligationHandlers(request, response);
        } catch (ObligationProcessingException e) {
            throw new PEPClientException("ObligationHandler processing failure",
                                         e);
        }
        return response;
    }

    /**
     * Calls out to the remote PEP and returns the response.
     * 
     * @param pepUrl
     *            the remote PEP to which to callout
     * @param authzRequest
     *            the authorization request to send to the PEP daemon
     * @return the response to the request
     * @throws PEPClientException
     *             thrown if there is a problem processing the request
     */
    protected Response performRequest(String pepUrl, Request authzRequest)
            throws PEPClientException {

        String b64Message= null;
        try {
            ByteArrayOutputStream out= new ByteArrayOutputStream();
            HessianOutput hout= new HessianOutput(out);
            hout.writeObject(authzRequest);
            hout.flush();
            b64Message= Base64.encodeBytes(out.toByteArray());
        } catch (IOException e) {
            log.error("Unable to serialize request object", e);
            throw new PEPClientException("Unable to serialize request object",
                                         e);
        }

        PostMethod postMethod= new PostMethod(pepUrl);
        try {
            RequestEntity requestEntity= new StringRequestEntity(b64Message,
                                                                 "application/octet-stream",
                                                                 "UTF-8");
            postMethod.setRequestEntity(requestEntity);
        } catch (UnsupportedEncodingException e) {
            throw new PEPClientException(e);
        }

        Response response= null;
        try {
            httpClient_.executeMethod(postMethod);
            if (postMethod.getStatusCode() == HttpStatus.SC_OK) {
                try {
                    InputStream is= new Base64.InputStream(postMethod.getResponseBodyAsStream());
                    HessianInput hin= new HessianInput(is);
                    response= (Response) hin.readObject(Response.class);
                } catch (IOException e) {
                    log.error("Unable to deserialize response object", e);
                    throw new PEPClientException("Unable to deserialize response object",
                                                 e);
                }
            }
            else {
                String error= postMethod.getStatusCode()
                        + " status code response from the PEP Server " + pepUrl;
                log.error(error);
                throw new PEPClientException(error);

            }
        } catch (IOException e) {
            log.error("Unable to read response from PEP Server " + pepUrl, e);
            throw new PEPClientException("Unable to read response from PEP Server "
                                                 + pepUrl,
                                         e);
        } finally {
            log.debug("release connection");
            postMethod.releaseConnection();
        }

        return response;
    }

    /**
     * Run the list of PIPs over the request.
     * 
     * @param request
     *            the request
     * @param pips
     *            PIPs to run over the request
     * @throws PIPProcessingException
     *             thrown if a PIP failed to populate the request
     */
    protected void runPolicyInformationPoints(Request request)
            throws PIPProcessingException {
        boolean pipApplied;
        for (PolicyInformationPoint pip : pips_) {
            if (log.isDebugEnabled()) {
                log.debug("applying PIP " + pip.getId());
            }
            pipApplied= pip.populateRequest(request);
            if (log.isErrorEnabled()) {
                log.debug("PIP " + pip.getId() + " applied: " + pipApplied);
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
     * @throws ObligationProcessingException
     *             thrown if there is a problem evaluating obligation handlers.
     */
    protected void runObligationHandlers(Request request, Response response)
            throws ObligationProcessingException {
        if (response == null)
            return;
        boolean ohApplied;
        List<Result> results= response.getResults();
        for (Result result : results) {
            for (ObligationHandler oh : obligationHandlers_) {
                if (log.isDebugEnabled()) {
                    log.debug("applying OH " + oh.getObligationId());
                }
                ohApplied= oh.evaluateObligation(request, result);
                if (log.isDebugEnabled()) {
                    log.debug("OH " + oh.getObligationId() + " applied: "
                            + ohApplied);
                }
            }
        }
    }

}