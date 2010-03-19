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
package org.glite.authz.common.profile;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.security.PEMUtils;

/**
 * XACML Grid Worker Node Authorization Profile v1.0.
 * 
 * Profile constants and utility methods.
 * 
 * @see http://edms.cern.ch/document/1058175
 * 
 * @version 1.0
 */
public class GridWNAuthorizationProfile extends GridAuthorizationProfile {

    /** The attribute id profile-id identifier, {@value} . */
    public static final String ID_ATTRIBUTE_PROFILE_ID= NS_ATTRIBUTE
            + "/profile-id";

    /** The attribute id user-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_USER_ID= NS_ATTRIBUTE + "/user-id";

    /** The attribute id group-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_GROUP_ID= NS_ATTRIBUTE
            + "/group-id";

    /** The attribute id primary group-id identifier: {@value} . */
    public static final String ID_ATTRIBUTE_PRIMARY_GROUP_ID= NS_ATTRIBUTE
            + "/group-id/primary";

    /** The obligation id map to environment identifier: {@value} . */
    public static final String ID_OBLIGATION_LOCAL_ENV_MAP= NS_OBLIGATION
            + "/local-environment-map";

    /** The obligation id map to POSIX environment identifier: {@value} . */
    public static final String ID_OBLIGATION_LOCAL_MAP_POSIX= NS_OBLIGATION
            + "/local-environment-map/posix";

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /** Identifier of the profile: {@value} */
    public static final String PROFILE_ID= NS_PROFILE + "/grid-wn/"
            + PROFILE_VERSION;

    /**
     * Creates a {@link Request} with the given user certificate, and chain,
     * resourceid and actionid.
     * 
     * @param certs
     *            the user certificate or proxy certificate, with chain
     * @param resourceid
     *            the resource id
     * @param actionid
     *            the action id
     * @return a new request
     * @throws ProfileProcessingException
     *             if the a certificate can not be converted to PEM format.
     */
    static public Request createRequest(X509Certificate[] certs,
            String resourceid, String actionid)
            throws ProfileProcessingException {
        Subject subject= createSubject(certs);
        Resource resource= createResource(resourceid);
        Action action= createAction(actionid);
        Request request= createRequest(subject, resource, action);
        return request;
    }

    /**
     * Creates a {@link Request} containing the given {@link Subject},
     * {@link Resource} and {@link Action}. The default {@link Environment} is
     * added to it.
     * 
     * @param subject
     *            the request subject
     * @param resource
     *            the request resource
     * @param action
     *            the request action
     * @return the request
     */
    public static Request createRequest(Subject subject, Resource resource,
            Action action) {
        return createRequest(subject, resource, action, createEnvironment());
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute} identified by
     * {@link Attribute#ID_SUB_KEY_INFO} and for value the certificates given as
     * parameter, encoded in PEM blocks.
     * 
     * @param cert
     *            the user certificate
     * @return the subject
     * @throws ProfileProcessingException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate cert)
            throws ProfileProcessingException {
        return createSubject(cert, null);
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute} identified by
     * {@link Attribute#ID_SUB_KEY_INFO} and for value the certificates given as
     * parameter, encoded in PEM blocks.
     * 
     * @param certs
     *            the user certificate and chain
     * @return the subject
     * @throws ProfileProcessingException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate[] certs)
            throws ProfileProcessingException {
        return createSubject(null, certs);
    }

    /**
     * Creates a {@link Subject} containing the {@link Attribute} identified by
     * {@link Attribute#ID_SUB_KEY_INFO} and for value the certificates given as
     * parameter, encoded in PEM blocks.
     * 
     * @param cert
     *            the user certificate
     * @param chain
     *            the user certificate chain
     * @return the subject
     * @throws ProfileProcessingException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate cert,
            X509Certificate[] chain) throws ProfileProcessingException {
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
            throw new ProfileProcessingException("Can not convert certificate to PEM format",
                                                 e);
        }
        Subject subject= new Subject();
        Attribute attrKeyInfo= new Attribute();
        attrKeyInfo.setId(Attribute.ID_SUB_KEY_INFO);
        attrKeyInfo.setDataType(Attribute.DT_STRING);
        attrKeyInfo.getValues().add(keyInfo);
        subject.getAttributes().add(attrKeyInfo);
        return subject;
    }

    /**
     * Creates a {@link Resource} containing the {@link Attribute} identified by
     * {@link Attribute#ID_RES_ID} with the value given as parameter.
     * 
     * @param resourceId
     *            The value of the resource-id attribute
     * @return the resource
     */
    public static Resource createResource(String resourceId) {
        Resource resource= new Resource();
        Attribute attrResourceId= new Attribute();
        attrResourceId.setId(Attribute.ID_RES_ID);
        attrResourceId.setDataType(Attribute.DT_STRING);
        attrResourceId.getValues().add(resourceId);
        resource.getAttributes().add(attrResourceId);
        return resource;
    }

    /**
     * Creates an {@link Action} containing the {@link Attribute} identified by
     * {@link Attribute#ID_ACT_ID} with the value given as parameter.
     * 
     * @param actionId
     *            The value of the action-id attribute
     * @return the action
     */
    public static Action createAction(String actionId) {
        Action action= new Action();
        Attribute attrActionId= new Attribute();
        attrActionId.setId(Attribute.ID_ACT_ID);
        attrActionId.setDataType(Attribute.DT_STRING);
        attrActionId.getValues().add(actionId);
        action.getAttributes().add(attrActionId);
        return action;
    }

    /**
     * Creates a base {@link Environment} containing the Attribute identified by
     * {@link #ID_ATTRIBUTE_PROFILE_ID} with value for the Grid WN AuthZ profile
     * identifier.
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

    public static Obligation getObligationPosixMapping(Response response)
            throws ProfileProcessingException {
        Obligation posixMappingObligation= getObligation(response,
                                                         Result.DECISION_PERMIT,
                                                         ID_OBLIGATION_LOCAL_MAP_POSIX);
        return posixMappingObligation;
    }

    public static String getAttributeAssignmentUserId(
            Obligation posixMappingObligation) {
        return null;
    }

    public static String[] getAttributeAssignmentGroupIds(
            Obligation posixMappingObligation) {
        return null;
    }

    public static String getAttributeAssignmentPrimaryGroupId(
            Obligation posixMappingObligation) {
        return null;
    }

    /** Prevents instantiation */
    private GridWNAuthorizationProfile() {
        super();
    }
}
