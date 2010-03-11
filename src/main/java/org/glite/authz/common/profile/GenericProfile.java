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

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;

/**
 * GenericProfile
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 */
public class GenericProfile {

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
        request.getSubjects().add(subject);
        request.getResources().add(resource);
        request.setAction(action);
        request.setEnvironment(environment);
        return request;
    }

    /** Prevents instantiation */
    protected GenericProfile() {
    }

}