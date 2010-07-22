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
import org.glite.authz.common.profile.AuthorizationProfileConstants;
import org.glite.authz.common.security.PEMUtils;

/**
 * Base authorization profile containing helper methods to build request and
 * parse response.
 */
public abstract class AuthorizationProfile implements Profile {

    /** profile ID */
    private String profileId_;

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

    /**
     * Creates a {@link Resource} containing the {@link Attribute}
     * {@value AuthorizationProfileConstants#ID_ATTRIBUTE_RESOURCE_ID} with the
     * value given as parameter.
     * 
     * @param resourceId
     *            The value of the resource-id attribute
     * @return the resource
     */
    public Resource createResourceId(String resourceId) {
        Resource resource= new Resource();
        Attribute attrResourceId= new Attribute();
        attrResourceId.setId(AuthorizationProfileConstants.ID_ATTRIBUTE_RESOURCE_ID);
        attrResourceId.setDataType(AuthorizationProfileConstants.DATATYPE_STRING);
        attrResourceId.getValues().add(resourceId);
        resource.getAttributes().add(attrResourceId);
        return resource;
    }

    /**
     * Creates an {@link Action} containing the {@link Attribute} {@value
     * AuthorizationProfileConstants.ID_ATTRIBUTE_ACTION_ID} with the value
     * given as parameter.
     * 
     * @param actionId
     *            The value of the action-id attribute
     * @return the action
     */
    public Action createActionId(String actionId) {
        Action action= new Action();
        Attribute attrActionId= new Attribute();
        attrActionId.setId(AuthorizationProfileConstants.ID_ATTRIBUTE_ACTION_ID);
        attrActionId.setDataType(AuthorizationProfileConstants.DATATYPE_STRING);
        attrActionId.getValues().add(actionId);
        action.getAttributes().add(attrActionId);
        return action;
    }

    /**
     * Creates a {@link Request} containing the given {@link Subject},
     * {@link Resource} and {@link Action}. The {@link Environment} with the
     * profile identifier is added to it.
     * 
     * @param subject
     *            the request subject
     * @param resource
     *            the request resource
     * @param action
     *            the request action
     * @return the request
     * 
     * @see #createRequest(Subject, Resource, Action, Environment)
     * @see #createEnvironmentProfileId(String)
     * @see #getProfileId()
     */
    public Request createRequest(Subject subject, Resource resource,
            Action action) {
        return createRequest(subject,
                             resource,
                             action,
                             createEnvironmentProfileId(getProfileId()));
    }

    /**
     * Gets the obligation identified by id from the response for a given
     * decision.
     * 
     * @param response
     *            the response to process
     * @param decision
     *            the decision to match
     * @param obligationId
     *            the obligation id to match
     * @return the matching obligation
     * @throws ProfileException
     *             if the response doesn't contain the result for the decision,
     *             or obligation matching the id.
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
                throw new ProfileException("No decision "
                        + Result.decisionToString(decision) + " found: "
                        + result.getDecisionString());
            }
        }
        return null;
    }

    /**
     * Constructor
     */
    protected AuthorizationProfile(String profileId) {
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

    /**
     * Creates a base {@link Environment} containing the Attribute
     * {@value AuthorizationProfileConstants#ID_ATTRIBUTE_PROFILE_ID} with the
     * profile identifier
     * 
     * @return the environment
     */
    public Environment createEnvironmentProfileId(String profileId) {
        Environment environment= new Environment();
        Attribute attrProfileId= new Attribute();
        attrProfileId.setId(AuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID);
        attrProfileId.setDataType(AuthorizationProfileConstants.DATATYPE_ANY_URI);
        attrProfileId.getValues().add(profileId);
        environment.getAttributes().add(attrProfileId);
        return environment;
    }

/**
         * Creates a {@link Request} with the given end entity certificate or proxy
         * certificate, with chain, the resourceid and the actionid. The subject attribute is {@link AuthorizationProfileConstants#ID_A
         * 
         * @param certs
         *            the user certificate or proxy certificate, with chain
         * @param resourceid
         *            the resource id
         * @param actionid
         *            the action id
         * @return a new request
         * @throws ProfileException
         *             if the a certificate can not be converted to PEM format.
         */
    public Request createRequest(X509Certificate[] certs, String resourceid,
            String actionid) throws ProfileException {
        Subject subject= createSubjectKeyInfo(certs);
        Resource resource= createResourceId(resourceid);
        Action action= createActionId(actionid);
        Request request= createRequest(subject, resource, action);
        return request;
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute}
     * {@value org.glite.authz.common.model.Attribute#ID_SUB_KEY_INFO} and for
     * value the certificates given as parameter, encoded in PEM blocks.
     * 
     * @param cert
     *            the user certificate
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public Subject createSubjectKeyInfo(X509Certificate cert)
            throws ProfileException {
        return createSubjectKeyInfo(cert, null);
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute}
     * {@value org.glite.authz.common.model.Attribute#ID_SUB_KEY_INFO} and for
     * value the certificates given as parameter, encoded in PEM blocks.
     * 
     * @param certs
     *            the user certificate and chain
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public Subject createSubjectKeyInfo(X509Certificate[] certs)
            throws ProfileException {
        return createSubjectKeyInfo(null, certs);
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute}
     * {@value AuthorizationProfileConstants#ID_ATTRIBUTE_SUBJECT_KEY_INFO} and
     * for value the certificates given as parameter, encoded in PEM blocks.
     * 
     * @param cert
     *            the user certificate
     * @param chain
     *            the user certificate chain
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate in PEM
     *             format
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
        attrKeyInfo.setId(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_KEY_INFO);
        attrKeyInfo.setDataType(AuthorizationProfileConstants.DATATYPE_STRING);
        attrKeyInfo.getValues().add(keyInfo);
        subject.getAttributes().add(attrKeyInfo);
        return subject;
    }

    /**
     * Gets the obligation
     * {@value AuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP} from
     * the result with a <code>Permit</code> decision
     * 
     * @param response
     *            the response to process
     * @return the POSIX mapping obligation, with decision Permit
     * @throws ProfileException
     *             if no decision Permit or no POSIX mapping obligation is
     *             found.
     */
    public Obligation getObligationPosixMapping(Response response)
            throws ProfileException {
        Obligation posixMappingObligation= getObligation(response,
                                                         Result.DECISION_PERMIT,
                                                         AuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP);
        return posixMappingObligation;
    }

    /**
     * Gets the mandatory POSIX user-id (login name) from the
     * {@value AuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP}
     * obligation
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return the POSIX login name to map
     * @throws ProfileException
     *             if the obligation is not a
     *             {@value AuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP}
     *             , or if the mandatory user-id attribute assignment is not
     *             contained in the obligation, or if the user-id login name is
     *             empty or null.
     */
    public String getAttributeAssignmentUserId(Obligation posixMappingObligation)
            throws ProfileException {
        if (!AuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not "
                    + AuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP
                    + " but " + posixMappingObligation.getId());
        }
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID.equals(id)) {
                String userId= Strings.safeTrimOrNullString(attribute.getValue());
                if (userId == null) {
                    throw new ProfileException("Attribute assignment "
                            + AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID
                            + " found in obligation, but with an empty or null value");
                }
                return userId;
            }
        }
        // attribute user-id not found
        throw new ProfileException("Mandatory attribute assignment "
                + AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID
                + " not found in obligation "
                + AuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP);
    }

    /**
     * Gets the list of POSIX group-ids (group names) from the obligation
     * {@value AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID}
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return list of POSIX group names, can be empty if the group-id attribute
     *         assignments are not contained in the obligation.
     * @throws ProfileException
     *             if the obligation is not a {@value
     *             AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID}
     */
    public List<String> getAttributeAssignmentGroupIds(
            Obligation posixMappingObligation) throws ProfileException {
        if (!AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not "
                    + AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID);
        }
        List<String> groupIds= new ArrayList<String>();
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (AuthorizationProfileConstants.ID_ATTRIBUTE_GROUP_ID.equals(id)) {
                groupIds.add(attribute.getValue());
            }
        }
        return groupIds;
    }

    /**
     * Gets the POSIX primary group-id (group name) from the obligation
     * {@value AuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP}
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return the POSIX group name, can be <code>null</code> if the attribute
     *         is not contained in the obligation.
     * @throws ProfileException
     *             if the obligation is not a
     *             {@value AuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP}
     */
    public String getAttributeAssignmentPrimaryGroupId(
            Obligation posixMappingObligation) throws ProfileException {
        if (!AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID.equals(posixMappingObligation.getId())) {
            throw new ProfileException("Obligation is not "
                    + AuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID);
        }
        List<AttributeAssignment> attributes= posixMappingObligation.getAttributeAssignments();
        for (AttributeAssignment attribute : attributes) {
            String id= attribute.getAttributeId();
            if (AuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP_ID.equals(id)) {
                String groupId= attribute.getValue();
                return groupId;
            }
        }
        return null;
    }

}