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
package org.glite.authz.pep.profile;

/**
 * XACML Grid Worker Node Authorization Profile v1.0.
 * <p>
 * Profile constants and utility methods.
 * 
 * @see http://edms.cern.ch/document/1058175
 * 
 * @version 1.0
 */
public final class GridWNAuthorizationProfile extends AuthorizationProfile {

    /** Singleton */
    private static GridWNAuthorizationProfile SINGLETON= null;

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /**
     * Identifier of the XACML Grid Worker Node Authorization Profile v1.0:
     * {@value}
     */
    public static final String PROFILE_ID= NS_PROFILE + SEPARATOR + "grid-wn"
            + SEPARATOR + PROFILE_VERSION;

    /** Action value <b>execute</b>: {@value} */
    public static final String ACTION_EXECUTE= NS_ACTION + SEPARATOR
            + "execute";

    /**
     * Gets the Grid Worker Node Authorization Profile instance
     * 
     * @return
     */
    public static synchronized GridWNAuthorizationProfile getInstance() {
        if (SINGLETON == null) {
            SINGLETON= new GridWNAuthorizationProfile();
        }
        return SINGLETON;
    }

    /**
     * Constructor
     */
    private GridWNAuthorizationProfile() {
        super(PROFILE_ID);
    }
}
