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
package org.glite.authz.common.profile;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;

/**
 * XACML Grid Computing Element Authorization Profile v1.0.
 * 
 * Profile constants and utility methods.
 * 
 * @see TODO document url
 * 
 * @version 1.0
 */
public final class GridCEAuthorizationProfile extends GridAuthorizationProfile {

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /** Identifier of the profile: {@value} */
    public static final String PROFILE_ID= NS_PROFILE + "/grid-ce/"
            + PROFILE_VERSION;

    /**
     * Creates a base {@link Environment} containing the Attribute
     * {@value #ID_ATTRIBUTE_PROFILE_ID} with value for the Grid CE AuthZ
     * profile identifier.
     * 
     * @return the environment
     */
    public static Environment createEnvironment() {
        Environment environment= new Environment();
        Attribute attrProfileId= new Attribute();
        attrProfileId.setId(ID_ATTRIBUTE_PROFILE_ID);
        attrProfileId.setDataType(Attribute.DT_ANY_URI);
        attrProfileId.getValues().add(PROFILE_ID);
        environment.getAttributes().add(attrProfileId);
        return environment;
    }

    /** Prevents instantiation */
    private GridCEAuthorizationProfile() {
        super();
    }

}
