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
package org.glite.authz.pep.profile;

import org.glite.authz.common.profile.AuthorizationProfileConstants;

/**
 * XACML Grid Computing Element Authorization Profile v1.0.
 * <p>
 * Profile constants and utility methods.
 * 
 * @see https://edms.cern.ch/document/1078881
 * 
 * @version 1.0
 */
public final class GridCEAuthorizationProfile extends AuthorizationProfile {

    /** Singleton */
    private static GridCEAuthorizationProfile SINGLETON= null;

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /** Identifier of the profile: {@value} */
    public static final String PROFILE_ID= AuthorizationProfileConstants.NS_PROFILE
            + "/grid-ce/" + PROFILE_VERSION;

    /** Prevents instantiation */
    private GridCEAuthorizationProfile() {
        super(PROFILE_ID);
    }

    /**
     * Gets the Grid Computing Element Authorization Profile instance
     * 
     * @return
     */
    public static synchronized GridCEAuthorizationProfile getInstance() {
        if (SINGLETON == null) {
            SINGLETON= new GridCEAuthorizationProfile();
        }
        return SINGLETON;
    }
}
