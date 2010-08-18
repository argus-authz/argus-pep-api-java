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

    private static final String ACTION_CE_PREFIX= NS_ACTION + SEPARATOR + "ce";

    private static final String ACTION_CE_JOB_PREFIX= ACTION_CE_PREFIX
            + SEPARATOR + "job";

    private static final String ACTION_CE_LEASE_PREFIX= ACTION_CE_PREFIX
            + SEPARATOR + "lease";

    private static final String ACTION_CE_DELEGATION_PREFIX= ACTION_CE_PREFIX
            + SEPARATOR + "delegation";

    private static final String ACTION_CE_SUBSCRIPTION_PREFIX= ACTION_CE_PREFIX
            + SEPARATOR + "subscription";

    /** Action value <b>job submit</b>: {@value} */
    public static final String ACTION_JOB_SUBMIT= ACTION_CE_JOB_PREFIX
            + SEPARATOR + "submit";

    /** Action value <b>job terminate</b>: {@value} */
    public static final String ACTION_JOB_TERMINATE= ACTION_CE_JOB_PREFIX
            + SEPARATOR + "terminate";

    /** Action value <b>job get info</b>: {@value} */
    public static final String ACTION_JOB_GET_INFO= ACTION_CE_JOB_PREFIX
            + SEPARATOR + "get-info";

    /** Action value <b>job manage</b>: {@value} */
    public static final String ACTION_JOB_MANAGE= ACTION_CE_JOB_PREFIX
            + SEPARATOR + "manage";

    /** Action value <b>lease get info</b>: {@value} */
    public static final String ACTION_LEASE_GET_INFO= ACTION_CE_LEASE_PREFIX
            + SEPARATOR + "get-info";

    /** Action value <b>lease manage</b>: {@value} */
    public static final String ACTION_LEASE_MANAGE= ACTION_CE_LEASE_PREFIX
            + SEPARATOR + "manage";

    /** Action value <b>get info</b>: {@value} */
    public static final String ACTION_GET_INFO= ACTION_CE_PREFIX + SEPARATOR
            + "get-info";

    /** Action value <b>delegation get info</b>: {@value} */
    public static final String ACTION_DELEGATION_GET_INFO= ACTION_CE_DELEGATION_PREFIX
            + SEPARATOR + "get-info";

    /** Action value <b>delegation manage</b>: {@value} */
    public static final String ACTION_DELEGATION_MANAGE= ACTION_CE_DELEGATION_PREFIX
            + SEPARATOR + "manage";

    /** Action value <b>subscription get info</b>: {@value} */
    public static final String ACTION_SUBSCRIPTION_GET_INFO= ACTION_CE_SUBSCRIPTION_PREFIX
            + SEPARATOR + "get-info";

    /** Action value <b>subscription manage</b>: {@value} */
    public static final String ACTION_SUBSCRIPTION_MANAGE= ACTION_CE_SUBSCRIPTION_PREFIX
            + SEPARATOR + "manage";

    /** Singleton */
    private static GridCEAuthorizationProfile SINGLETON= null;

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /** Identifier of the XACML Grid Computing Element Authorization Profile v1.0: {@value} */
    public static final String PROFILE_ID= NS_PROFILE + SEPARATOR + "grid-ce"
            + SEPARATOR + PROFILE_VERSION;

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
