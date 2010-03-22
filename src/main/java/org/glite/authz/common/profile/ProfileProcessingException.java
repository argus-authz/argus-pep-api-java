/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
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
package org.glite.authz.common.profile;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;

/**
 * Exception for profile processing
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class ProfileProcessingException extends AuthorizationServiceException {

    /** Serial version */
    private static final long serialVersionUID= 6696042569341460539L;

    /** The result decision string: Permit, Deny, NotApplicable or Indeterminate */
    private String decisionString_= null;

    /** The status message */
    private String status_= null;

    /** The status code message */
    private String statusCode_= null;

    /**
     * Default constructor.
     */
    public ProfileProcessingException() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param message
     *            the error message
     */
    public ProfileProcessingException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * 
     * @param message
     *            the error message
     * @param result
     *            the result
     */
    public ProfileProcessingException(String message, Result result) {
        super(message);
        decisionString_= result.getDecisionString();
        Status status= result.getStatus();
        if (status != null) {
            status_= status.getMessage();
            StatusCode statusCode= status.getCode();
            if (statusCode != null) {
                statusCode_= statusCode.getCode();
            }
        }
    }

    /**
     * Constructor.
     * 
     * @param cause
     *            the exception cause
     */
    public ProfileProcessingException(Exception cause) {
        super(cause);
    }

    /**
     * Constructor.
     * 
     * @param message
     *            the exception message
     * @param cause
     *            the exception cause
     */
    public ProfileProcessingException(String message, Exception cause) {
        super(message, cause);
    }

    /**
     * Gets the result decision string if available.
     * 
     * @return the decision XACML string or <code>null</code>
     */
    public String getDecisionString() {
        return decisionString_;
    }

    /**
     * Gets the result status message if available.
     * 
     * @return the status message or <code>null</code>
     */
    public String getStatus() {
        return status_;
    }

    /**
     * Gets the result status code if available.
     * 
     * @return the status code or <code>null</code>
     */
    public String getStatusCode() {
        return statusCode_;
    }
}
