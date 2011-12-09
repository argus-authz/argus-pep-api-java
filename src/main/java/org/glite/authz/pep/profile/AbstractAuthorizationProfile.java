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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.Strings;
import org.glite.authz.common.security.PEMUtils;

/**
 * Base authorization profile containing helper methods to build request and
 * parse response.
 */
public abstract class AbstractAuthorizationProfile implements
        AuthorizationProfile {

    /** profile ID */
    private String profileId_;

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.TestAuthorizationProfile#createRequest(org
     * .glite.authz.common.model.Subject, org.glite.authz.common.model.Resource,
     * org.glite.authz.common.model.Action,
     * org.glite.authz.common.model.Environment)
     */
    public Request createRequest(Subject subject, Resource resource,
            Action action, Environment environment) {
        Request request= new Request();
        if (subject != null) {
            request.getSubjects().add(subject);
        }
        if (resource != null) {
            request.getResources().add(resource);
        }
        if (action != null) {
            request.setAction(action);
        }
        if (environment != null) {
            request.setEnvironment(environment);
        }
        return request;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.TestAuthorizationProfile#createResourceId
     * (java.lang.String)
     */
    public Resource createResourceId(String resourceId) {
        Attribute attrResourceId= new Attribute();
        attrResourceId.setId(getResourceIdAttributeIdentifer());
        attrResourceId.setDataType(getResourceIdDatatype());
        attrResourceId.getValues().add(resourceId);
        Resource resource= new Resource();
        resource.getAttributes().add(attrResourceId);
        return resource;
    }

    /**
     * Returns the attribute identifier for the subject key-info attribute:
     * {@value Attribute#ID_SUB_KEY_INFO}
     * 
     * @return subject key-info attribute identifier
     */
    protected String getSubjectKeyInfoAttributeIdentifer() {
        return Attribute.ID_SUB_KEY_INFO;
    }

    /**
     * Returns the attribute data type for the subject key-info attribute, defined by
     * the profile.
     * 
     * @return subject key-info attribute data type
     */
    abstract protected String getSubjectKeyInfoDatatype();

    /**
     * Returns the attribute identifier for the profile-id attribute, defined by
     * the profile.
     * 
     * @return profile-id attribute identifier
     */
    abstract protected String getProfileIdAttributeIdentifer();

    /**
     * Returns the attribute data type for the profile-id attribute:
     * {@value Attribute#DT_ANY_URI}
     * 
     * @return profile-id attribute data type
     */
    protected String getProfileIdDatatype() {
        return Attribute.DT_ANY_URI;
    }

    /**
     * Returns the attribute identifier for the resource-id attribute:
     * {@value Attribute#ID_RES_ID}
     * 
     * @return resource-id attribute identifier
     */
    protected String getResourceIdAttributeIdentifer() {
        return Attribute.ID_RES_ID;
    }

    /**
     * Returns the attribute data type for the resource-id attribute:
     * {@value Attribute#DT_STRING}
     * 
     * @return resource-id attribute datatype
     */
    protected String getResourceIdDatatype() {
        return Attribute.DT_STRING;
    }

    /**
     * Returns the attribute identifier for the action-id attribute:
     * {@value Attribute#ID_ACT_ID}
     * 
     * @return action-id attribute identifier
     */
    protected String getActionIdAttributeIdentifer() {
        return Attribute.ID_ACT_ID;
    }

    /**
     * Returns the attribute data type for the action-id attribute:
     * {@value Attribute#DT_STRING}
     * 
     * @return action-id attribute datatype
     */
    protected String getActionIdDatatype() {
        return Attribute.DT_STRING;
    }

    /**
     * TODO doc
     * 
     * @return
     */
    abstract protected String getMapUserToPOSIXEnvironmentObligationIdentifier();

    /**
     * TODO doc
     * 
     * @return
     */
    abstract protected String getUserIdAttributeAssignmentIdentifier();

    /**
     * TODO doc
     * 
     * @return
     */
    abstract protected String getGroupIdAttributeAssignmentIdentifier();

    /**
     * TODO doc
     * 
     * @return
     */
    abstract protected String getPrimaryGroupIdAttributeAssignmentIdentifier();

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.TestAuthorizationProfile#createActionId(java
     * .lang.String)
     */
    public Action createActionId(String actionId) {
        Action action= new Action();
        Attribute attrActionId= new Attribute();
        attrActionId.setId(getActionIdAttributeIdentifer());
        attrActionId.setDataType(getActionIdDatatype());
        attrActionId.getValues().add(actionId);
        action.getAttributes().add(attrActionId);
        return action;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.TestAuthorizationProfile#createRequest(org
     * .glite.authz.common.model.Subject, org.glite.authz.common.model.Resource,
     * org.glite.authz.common.model.Action)
     */
    public Request createRequest(Subject subject, Resource resource,
            Action action) {
        return createRequest(subject,
                             resource,
                             action,
                             createEnvironmentProfileId(getProfileId()));
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#getObligation(org
     * .glite.authz.common.model.Response, int, java.lang.String)
     */
    public Obligation getObligation(Response response, int decision,
            String obligationId) throws ProfileException {
        List<Result> results= response.getResults();
        // should be only 1 result!!!!
        for (Result result : results) {
            if (result.getDecision() == decision) {
                List<Obligation> obligations= result.getObligations();
                for (Obligation obligation : obligations) {
                    String id= obligation.getId();
                    if (obligation.getFulfillOn() == decision
                            && obligationId.equals(id)) {
                        return obligation;
                    }
                }
                throw new ProfileException("No obligation " + obligationId
                        + " found");
            }
            else {
                String errorMessage= "No decision "
                        + Result.decisionToString(decision) + " found: "
                        + result.getDecisionString();
                String statusMessage= result.getStatus().getMessage();
                if (statusMessage != null) {
                    errorMessage+= ". Status: " + statusMessage;
                }
                throw new ProfileException(errorMessage);
            }
        }
        return null;
    }

    /**
     * Constructor
     */
    protected AbstractAuthorizationProfile(String profileId) {
        profileId_= Strings.safeTrimOrNullString(profileId);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.Profile#getProfileId()
     */
    public String getProfileId() {
        return profileId_;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#
     * createEnvironmentProfileId(java.lang.String)
     */
    public Environment createEnvironmentProfileId(String profileId) {
        Environment environment= new Environment();
        Attribute attrProfileId= new Attribute();
        attrProfileId.setId(getProfileIdAttributeIdentifer());
        attrProfileId.setDataType(getProfileIdDatatype());
        attrProfileId.getValues().add(profileId);
        environment.getAttributes().add(attrProfileId);
        return environment;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#createRequest(java
     * .security.cert.X509Certificate[], java.lang.String, java.lang.String)
     */
    public Request createRequest(X509Certificate[] certs, String resourceid,
            String actionid) throws ProfileException {
        Subject subject= createSubjectKeyInfo(certs);
        Resource resource= createResourceId(resourceid);
        Action action= createActionId(actionid);
        Request request= createRequest(subject, resource, action);
        return request;
    }

    public Request createRequest(X509Certificate[] certs, String resourceid,
            String actionid, String profileid) throws ProfileException {
        Subject subject= createSubjectKeyInfo(certs);
        Resource resource= createResourceId(resourceid);
        Action action= createActionId(actionid);
        Environment environment= createEnvironmentProfileId(profileid);
        Request request= createRequest(subject, resource, action, environment);
        return request;
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.AuthorizationProfile#createSubjectKeyInfo
     * (java.security.cert.X509Certificate)
     */
    public Subject createSubjectKeyInfo(X509Certificate cert)
            throws ProfileException {
        return createSubjectKeyInfo(cert, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.glite.authz.pep.profile.AuthorizationProfile#createSubjectKeyInfo
     * (java.security.cert.X509Certificate[])
     */
    public Subject createSubjectKeyInfo(X509Certificate[] certs)
            throws ProfileException {
        return createSubjectKeyInfo(null, certs);
    }

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
        List<X509Certificate> certs= new ArrayList<X509Certificate>();
        if (cert != null) {
            certs.add(cert);
        }
        if (chain != null) {
            for (X509Certificate chainCert : chain) {
                certs.add(chainCert);
            }
        }
        String keyInfo;
        try {
            keyInfo= PEMUtils.certificatesToPEMString(certs);
        } catch (IOException e) {
            throw new ProfileException("Can not convert certificate to PEM format",
                                       e);
        }
        Subject subject= new Subject();
        Attribute attrKeyInfo= new Attribute();
        attrKeyInfo.setId(getSubjectKeyInfoAttributeIdentifer());
        attrKeyInfo.setDataType(getSubjectKeyInfoDatatype());
        attrKeyInfo.getValues().add(keyInfo);
        subject.getAttributes().add(attrKeyInfo);
        return subject;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#
     * getObligationPosixMapping(org.glite.authz.common.model.Response)
     */
    public Obligation getObligationPosixMapping(Response response)
            throws ProfileException {
        Obligation posixMappingObligation= getObligation(response,
                                                         Result.DECISION_PERMIT,
                                                         getMapUserToPOSIXEnvironmentObligationIdentifier());
        return posixMappingObligation;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#
     * getAttributeAssignmentUserId(org.glite.authz.common.model.Obligation)
     */
    public String getAttributeAssignmentUserId(Obligation posixMappingObligation)
            throws ProfileException {
        String obligationId= getMapUserToPOSIXEnvironmentObligationIdentifier();
        if (!obligationId.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not " + obligationId
                    + " but " + posixMappingObligation.getId());
        }
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        String attributeAssignmentId= getUserIdAttributeAssignmentIdentifier();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (attributeAssignmentId.equals(id)) {
                String userId= Strings.safeTrimOrNullString(attribute.getValue());
                if (userId == null) {
                    throw new ProfileException("Attribute assignment "
                            + attributeAssignmentId
                            + " found in obligation, but with an empty or null value");
                }
                return userId;
            }
        }
        // attribute user-id not found
        throw new ProfileException("Mandatory attribute assignment "
                + attributeAssignmentId + " not found in obligation "
                + obligationId);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#
     * getAttributeAssignmentGroupIds(org.glite.authz.common.model.Obligation)
     */
    public List<String> getAttributeAssignmentGroupIds(
            Obligation posixMappingObligation) throws ProfileException {
        String obligationId= getMapUserToPOSIXEnvironmentObligationIdentifier();
        if (!obligationId.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not " + obligationId);
        }
        List<String> groupIds= new ArrayList<String>();
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        String attributeAssignmentId= getGroupIdAttributeAssignmentIdentifier();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (attributeAssignmentId.equals(id)) {
                groupIds.add(attribute.getValue());
            }
        }
        return groupIds;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.glite.authz.pep.profile.AuthorizationProfile#
     * getAttributeAssignmentPrimaryGroupId
     * (org.glite.authz.common.model.Obligation)
     */
    public String getAttributeAssignmentPrimaryGroupId(
            Obligation posixMappingObligation) throws ProfileException {
        String obligationId= getMapUserToPOSIXEnvironmentObligationIdentifier();
        if (!obligationId.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not " + obligationId);
        }
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        String attributeAssignmentId= getPrimaryGroupIdAttributeAssignmentIdentifier();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (attributeAssignmentId.equals(id)) {
                String groupId= attribute.getValue();
                return groupId;
            }
        }
        return null;
    }

}