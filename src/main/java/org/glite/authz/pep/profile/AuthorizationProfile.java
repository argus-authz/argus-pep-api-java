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

import java.security.cert.X509Certificate;
import java.util.List;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Subject;

/**
 * Authorization Profile Interface. Basic functionalities.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public interface AuthorizationProfile extends Profile {

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
            Action action, Environment environment);

    /**
     * Creates a {@link Resource} containing the <b>resource-id</b>
     * {@link Attribute} with the value given as parameter.
     * 
     * @param resourceId
     *            The value of the resource-id attribute
     * @return the resource
     */
    public Resource createResourceId(String resourceId);

    /**
     * Creates an {@link Action} containing the <b>action-id</b>
     * {@link Attribute} with the value given as parameter.
     * 
     * @param actionId
     *            The value of the action-id attribute
     * @return the action
     */
    public Action createActionId(String actionId);

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
            Action action);

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
            String obligationId) throws ProfileException;

    /**
     * Creates a base {@link Environment} containing the <b>profile-id</b>
     * Attribute with the profile identifier
     * 
     * @param profileId
     *            the profile ID value
     * @return the environment
     */
    public Environment createEnvironmentProfileId(String profileId);

    /**
     * Creates a {@link Request} with the given end entity X.509 certificate or
     * proxy (with its chain), the resource-id and the action-id.
     * 
     * @param certs
     *            the user X.5099 certificate or proxy, with its chain
     * @param resourceId
     *            the resource id
     * @param actionId
     *            the action id
     * @return a new request
     * @throws ProfileException
     *             if the a certificate can not be read
     * @see #createSubjectKeyInfo(X509Certificate[])
     * @see #createResourceId(String)
     * @see #createActionId(String)
     * @see #createRequest(Subject, Resource, Action)
     */
    public Request createRequest(X509Certificate[] certs, String resourceId,
            String actionId) throws ProfileException;

    /**
     * Creates a {@link Request} with the given end entity X.509 certificate or
     * proxy (with its chain) the resource-id, the action-id and the profile-id.
     * 
     * @param certs
     *            the user X.5099 certificate or proxy, with its chain
     * @param resourceId
     *            the resource id
     * @param actionId
     *            the action id
     * @return a new request
     * @throws ProfileException
     *             if the a certificate can not be read
     * @see #createSubjectKeyInfo(X509Certificate[])
     * @see #createResourceId(String)
     * @see #createActionId(String)
     * @see #createEnvironmentProfileId(String)
     * @see #createRequest(Subject, Resource, Action, Environment)
     */
    public Request createRequest(X509Certificate[] certs, String resourceid,
            String actionid, String profileId) throws ProfileException;

    /**
     * Creates a {@link Subject} containing the <b>subject-id</b>
     * {@link Attribute} with the value given as parameter.
     * 
     * @param subjectId
     *            The X500name of the subject (user DN)
     * @return the subject
     */
    public Subject createSubjectId(String subjectId);

    /**
     * Creates a {@link Subject} containing the <b>key-info</b>
     * {@link Attribute} and for value the certificates given as parameter.
     * 
     * @param cert
     *            the user certificate
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate
     */
    public Subject createSubjectKeyInfo(X509Certificate cert)
            throws ProfileException;

    /**
     * Creates a {@link Subject} containing the <b>key-info</b>
     * {@link Attribute} and for value the certificates given as parameter.
     * 
     * @param certs
     *            the user certificate and chain
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate
     */
    public Subject createSubjectKeyInfo(X509Certificate[] certs)
            throws ProfileException;

    /**
     * Creates a {@link Subject} containing the <b>key-info</b>
     * {@link Attribute} and for value the certificates given as parameter
     * 
     * @param cert
     *            the user certificate
     * @param chain
     *            the user certificate chain
     * @return the subject
     * @throws ProfileException
     *             if an error occurs while converting a certificate
     */
    public Subject createSubjectKeyInfo(X509Certificate cert,
            X509Certificate[] chain) throws ProfileException;

    /**
     * Gets the <b>posix env map</b> {@link Obligation} from the result with a
     * <code>Permit</code> decision
     * 
     * @param response
     *            the response to process
     * @return the POSIX mapping obligation, with decision Permit
     * @throws ProfileException
     *             if no decision Permit or no POSIX mapping obligation is
     *             found.
     */
    public Obligation getObligationPosixMapping(Response response)
            throws ProfileException;

    /**
     * Gets the mandatory POSIX user-id (login name) from the <b>posix env
     * map</b> {@link Obligation}
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return the POSIX login name to map
     * @throws ProfileException
     *             if the obligation is not a <b>posix env map</b> , or if the
     *             mandatory user-id attribute assignment is not contained in
     *             the obligation, or if the user-id login name is empty or
     *             null.
     */
    public String getAttributeAssignmentUserId(Obligation posixMappingObligation)
            throws ProfileException;

    /**
     * Gets the list of POSIX group-ids (group names) from the <b>posix env
     * map</b> {@link Obligation}
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return list of POSIX group names, can be empty if the group-id attribute
     *         assignments are not contained in the obligation.
     * @throws ProfileException
     *             if the obligation is not a <b>posix env map</b>
     */
    public List<String> getAttributeAssignmentGroupIds(
            Obligation posixMappingObligation) throws ProfileException;

    /**
     * Gets the POSIX primary group-id (group name) from the <b>posix env
     * map</b> {@link Obligation}
     * 
     * @param posixMappingObligation
     *            the posix mapping obligation
     * @return the POSIX group name, can be <code>null</code> if the attribute
     *         is not contained in the obligation.
     * @throws ProfileException
     *             if the obligation is not a <b>posix env map</b>
     */
    public String getAttributeAssignmentPrimaryGroupId(
            Obligation posixMappingObligation) throws ProfileException;

}
