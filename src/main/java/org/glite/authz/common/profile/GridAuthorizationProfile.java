/*
 * Copyright (c) Members of the EGEE Collaboration. 2010
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

/**
 * Abstract Grid authorization profile base class. Defines the namespaces used
 * in grid wn and ce profiles.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public abstract class GridAuthorizationProfile extends GenericProfile {

    /** The attribute namespace: {@value} . */
    public static final String NS_ATTRIBUTE= "http://glite.org/xacml/attribute";

    /** The action namespace: {@value} . */
    public static final String NS_ACTION= "http://glite.org/xacml/action";

    /** The datatype namespace: {@value} . */
    public static final String NS_DATATYPE= "http://glite.org/xacml/datatype";

    /** The profile namespace: {@value} . */
    public static final String NS_PROFILE= "http://glite.org/xacml/profile";

    /** The obligation namespace: {@value} . */
    public static final String NS_OBLIGATION= "http://glite.org/xacml/obligation";

    /** The algorithm namespace: {@value} . */
    public static final String NS_ALGORITHM= "http://glite.org/xacml/algorithm";

    /**
     * Default constructor
     */
    protected GridAuthorizationProfile() {
        super();
    }
}
