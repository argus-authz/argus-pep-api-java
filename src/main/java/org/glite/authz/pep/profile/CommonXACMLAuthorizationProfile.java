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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.util.Base64;

/**
 * EMI <a href="http://dci-sec.org/xacml/profile/common-authz/1.1">Common XACML
 * Authorization Profile v.1.1</a>
 * <p>
 * Profile constants and utility methods.
 * 
 * @version 1.1
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public final class CommonXACMLAuthorizationProfile extends
        AbstractAuthorizationProfile implements AuthorizationProfile {

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.AuthorizationProfile#createSubjectKeyInfo
     * (java.security.cert.X509Certificate,
     * java.security.cert.X509Certificate[])
     */
    public Subject createSubjectKeyInfo(X509Certificate cert,
            X509Certificate[] chain) throws ProfileException {
        List<X509Certificate> x509s= new ArrayList<X509Certificate>();
        if (cert != null) {
            x509s.add(cert);
        }
        if (chain != null) {
            for (X509Certificate chainCert : chain) {
                x509s.add(chainCert);
            }
        }

        Attribute attrKeyInfo= new Attribute();
        attrKeyInfo.setId(getSubjectKeyInfoAttributeIdentifer());
        attrKeyInfo.setDataType(getSubjectKeyInfoAttributeDatatype());

        for (X509Certificate x509 : x509s) {
            try {
                byte[] derBytes= x509.getEncoded();
                String base64Binary= Base64.encodeBytes(derBytes);
                attrKeyInfo.getValues().add(base64Binary);
            } catch (CertificateEncodingException e) {
                throw new ProfileException("Can not convert certificate to base64 binary format",
                                           e);
            }

        }

        Subject subject= new Subject();
        subject.getAttributes().add(attrKeyInfo);
        return subject;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getAttributeIdentiferProfileId()
     */
    public String getProfileIdAttributeIdentifer() {
        return CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getSubjectKeyInfoDatatype()
     */
    protected String getSubjectKeyInfoAttributeDatatype() {
        return CommonXACMLAuthorizationProfileConstants.DATATYPE_BASE64_BINARY;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getObligationIdentifierMapUserToPOSIXEnvironment()
     */
    public String getMapUserToPOSIXEnvironmentObligationIdentifier() {
        return CommonXACMLAuthorizationProfileConstants.ID_OBLIGATION_MAP_POSIX_USER;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierUserId()
     */
    public String getUserIdAttributeAssignmentIdentifier() {
        return CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierGroupId()
     */
    public String getGroupIdAttributeAssignmentIdentifier() {
        return CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP_ID;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AbstractAuthorizationProfile#
     * getAttributeAssignmentIdentifierPrimaryGroupId()
     */
    public String getPrimaryGroupIdAttributeAssignmentIdentifier() {
        return CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP_ID;
    }

    /** Prevents instantiation */
    private CommonXACMLAuthorizationProfile() {
        super(CommonXACMLAuthorizationProfileConstants.COMMON_XACML_AUTHZ_V1_1_PROFILE_ID);
    }

    /** Singleton instance */
    private static CommonXACMLAuthorizationProfile SINGLETON= null;

    /**
     * Gets the EMI Common XACML Authorization Profile instance
     * 
     * @return
     */
    public static synchronized CommonXACMLAuthorizationProfile getInstance() {
        if (SINGLETON == null) {
            SINGLETON= new CommonXACMLAuthorizationProfile();
        }
        return SINGLETON;
    }

}
