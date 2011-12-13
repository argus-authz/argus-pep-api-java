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

import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;

/**
 * XACML Grid Worker Node Authorization Profile v1.0.
 * <p>
 * Profile constants and utility methods.
 * 
 * @see <a href="http://edms.cern.ch/document/1058175">XACML Grid Worker Node
 *      Authorization Profile v1.0</a>
 * 
 * @version 1.0
 */
public final class GridWNAuthorizationProfile extends
        AbstractAuthorizationProfile {

    /** Singleton */
    private static GridWNAuthorizationProfile SINGLETON= null;

    /** Action value <b>execute</b>: {@value} */
    public static final String ACTION_EXECUTE= GLiteAuthorizationProfileConstants.NS_ACTION
            + GLiteAuthorizationProfileConstants.SEPARATOR + "execute";

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AstractAuthorizationProfile#
     * getAttributeIdentiferProfileId()
     */
    protected String getProfileIdAttributeIdentifer() {
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
     * Prevent instantiation.
     */
    private GridWNAuthorizationProfile() {
        super(GLiteAuthorizationProfileConstants.GRID_WN_AUTHZ_V1_PROFILE_ID);
    }
}
