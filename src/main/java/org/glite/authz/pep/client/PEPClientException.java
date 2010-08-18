/*
 * Copyright (c) Members of the EGEE Collaboration. 2010.
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
package org.glite.authz.pep.client;

import org.glite.authz.pep.PEPException;

/**
 * PEP client exception
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class PEPClientException extends PEPException {

    /**
     * Serial version uid
     */
    private static final long serialVersionUID= -1739763574977992063L;

    /**
     * Default constructor.
     */
    public PEPClientException() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param message
     */
    public PEPClientException(String message) {
        super(message);
    }

    /**
     * Constructor.
     * 
     * @param wrappedException
     */
    public PEPClientException(Exception wrappedException) {
        super(wrappedException);
    }

    /**
     * Constructor.
     * 
     * @param message
     * @param wrappedException
     */
    public PEPClientException(String message, Exception wrappedException) {
        super(message, wrappedException);
    }

}
