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
package org.glite.authz.common.profile;

import java.util.List;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Subject;

/**
 * Abstract generic profile containing helper methods to build request and parse
 * response.
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 */
public abstract class GenericProfile {

    /**
     * Creates a {@link Request} containing the given {@link Subject},
     * {@link Resource}, {@link Action} and {@link Environment}.
     * 
     * @param subject
     *            the request subject
     * @param resource
     *            the request resource
     * @param action
     *            the request action
     * @param environment
     *            the request environment
     * @return the request
     */
    public static Request createRequest(Subject subject, Resource resource,
            Action action, Environment environment) {
        Request request= new Request();
        if (subject != null) {
            request.getSubjects().add(subject);
        }
        if (resource != null) {
            request.getResources().add(resource);
        }
        if (action != null) {
            request.setAction(action);
        }
        if (environment != null) {
            request.setEnvironment(environment);
        }
        return request;
    }

    /**
     * Gets the obligation identified by id from the response for a given
     * decision.
     * 
     * @param response
     *            the response to process
     * @param decision
     *            the decision to match
     * @param obligationId
     *            the obligation id to match
     * @return the matching obligation
     * @throws ProfileProcessingException
     *             if the response doesn't contain the result for the decision,
     *             or obligation matching the id.
     */
    public static Obligation getObligation(Response response, int decision,
            String obligationId) throws ProfileProcessingException {
        List<Result> results= response.getResults();
        // should be only 1 result!!!!
        for (Result result : results) {
            if (result.getDecision() == decision) {
                List<Obligation> obligations= result.getObligations();
                for (Obligation obligation : obligations) {
                    String id= obligation.getId();
                    if (obligation.getFulfillOn() == decision
                            && obligationId.equals(id)) {
                        return obligation;
                    }
                }
                throw new ProfileProcessingException("No obligation "
                        + obligationId + " found", result);
            }
            else {
                throw new ProfileProcessingException("No decision "
                        + Result.decisionToString(decision) + " found: "
                        + result.getDecisionString(), result);
            }
        }
        return null;
    }

    /** Prevents instantiation */
    protected GenericProfile() {
    }

}