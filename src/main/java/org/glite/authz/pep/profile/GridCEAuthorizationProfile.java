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
package org.glite.authz.pep.profile;

import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;

/**
 * XACML Grid Computing Element Authorization Profile v1.0.
 * <p>
 * Profile constants and utility methods.
 * 
 * @see <a href="https://edms.cern.ch/document/1078881">XACML Grid Computing
 *      Element Authorization Profile v1.0</a>
 * 
 * @version 1.0
 */
public final class GridCEAuthorizationProfile extends
        AbstractAuthorizationProfile implements AuthorizationProfile {

    private static final String ACTION_CE_PREFIX= GLiteAuthorizationProfileConstants.NS_ACTION
            + GLiteAuthorizationProfileConstants.SEPARATOR + "ce";

    private static final String ACTION_CE_JOB_PREFIX= ACTION_CE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "job";

    private static final String ACTION_CE_LEASE_PREFIX= ACTION_CE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "lease";

    private static final String ACTION_CE_DELEGATION_PREFIX= ACTION_CE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "delegation";

    private static final String ACTION_CE_SUBSCRIPTION_PREFIX= ACTION_CE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "subscription";

    /** Action value <b>job submit</b>: {@value} */
    public static final String ACTION_JOB_SUBMIT= ACTION_CE_JOB_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "submit";

    /** Action value <b>job terminate</b>: {@value} */
    public static final String ACTION_JOB_TERMINATE= ACTION_CE_JOB_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "terminate";

    /** Action value <b>job get info</b>: {@value} */
    public static final String ACTION_JOB_GET_INFO= ACTION_CE_JOB_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "get-info";

    /** Action value <b>job manage</b>: {@value} */
    public static final String ACTION_JOB_MANAGE= ACTION_CE_JOB_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "manage";

    /** Action value <b>lease get info</b>: {@value} */
    public static final String ACTION_LEASE_GET_INFO= ACTION_CE_LEASE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "get-info";

    /** Action value <b>lease manage</b>: {@value} */
    public static final String ACTION_LEASE_MANAGE= ACTION_CE_LEASE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "manage";

    /** Action value <b>get info</b>: {@value} */
    public static final String ACTION_GET_INFO= ACTION_CE_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "get-info";

    /** Action value <b>delegation get info</b>: {@value} */
    public static final String ACTION_DELEGATION_GET_INFO= ACTION_CE_DELEGATION_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "get-info";

    /** Action value <b>delegation manage</b>: {@value} */
    public static final String ACTION_DELEGATION_MANAGE= ACTION_CE_DELEGATION_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "manage";

    /** Action value <b>subscription get info</b>: {@value} */
    public static final String ACTION_SUBSCRIPTION_GET_INFO= ACTION_CE_SUBSCRIPTION_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "get-info";

    /** Action value <b>subscription manage</b>: {@value} */
    public static final String ACTION_SUBSCRIPTION_MANAGE= ACTION_CE_SUBSCRIPTION_PREFIX
            + GLiteAuthorizationProfileConstants.SEPARATOR + "manage";

    /** Singleton */
    private static GridCEAuthorizationProfile SINGLETON= null;

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getAttributeIdentiferProfileId()
     */
    public String getProfileIdAttributeIdentifer() {
        return GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getSubjectKeyInfoDatatype()
     */
    protected String getSubjectKeyInfoDatatype() {
        return GLiteAuthorizationProfileConstants.DATATYPE_STRING;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getObligationIdentifierMapPOSIXUser()
     */
    public String getMapUserToPOSIXEnvironmentObligationIdentifier() {
        return GLiteAuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierUserId()
     */
    public String getUserIdAttributeAssignmentIdentifier() {
        return GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierGroupId()
     */
    public String getGroupIdAttributeAssignmentIdentifier() {
        return GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierPrimaryGroupId()
     */
    public String getPrimaryGroupIdAttributeAssignmentIdentifier() {
        return GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP_ID;
    }

    /** Prevents instantiation */
    private GridCEAuthorizationProfile() {
        super(GLiteAuthorizationProfileConstants.GRID_CE_AUTHZ_V1_PROFILE_ID);
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
