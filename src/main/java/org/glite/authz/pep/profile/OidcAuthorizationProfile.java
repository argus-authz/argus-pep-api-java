/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * $Id$
 */

package org.glite.authz.pep.profile;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.OidcProfileConstants;

public class OidcAuthorizationProfile extends AbstractAuthorizationProfile
    implements AuthorizationProfile {

  private static OidcAuthorizationProfile singleton = null;

  public OidcAuthorizationProfile() {
    super(OidcProfileConstants.OIDC_XACML_AUTHZ_V1_0_PROFILE_ID);
  }

  public static synchronized OidcAuthorizationProfile getInstance() {
    if (singleton == null) {
      singleton = new OidcAuthorizationProfile();
    }
    return singleton;
  }

  public Request createRequest(String accessToken, String resourceId, String actionId) {
    Request request = new Request();
    request.setEnvironment(createEnvironment());

    Subject subj = new Subject();
    subj.getAttributes().add(createOidcAccessTokenAttribute(accessToken));
    request.getSubjects().add(subj);

    Resource resource = new Resource();
    resource.getAttributes()
      .add(createAttribute(OidcProfileConstants.ID_ATTRIBUTE_RESOURCE_ID, resourceId));
    request.getResources().add(resource);

    Action action = new Action();
    action.getAttributes()
      .add(createAttribute(OidcProfileConstants.ID_ATTRIBUTE_ACTION_ID, actionId));
    request.setAction(action);

    return request;
  }

  protected Environment createEnvironment() {
    Environment env = new Environment();
    env.getAttributes().add(createOidcProfileAttribute());
    return env;
  }

  protected Attribute createOidcAccessTokenAttribute(String accessToken) {
    return createAttribute(OidcProfileConstants.ID_ATTRIBUTE_OIDC_ACCESS_TOKEN, accessToken);
  }

  protected Attribute createOidcProfileAttribute() {
    return createAttribute(OidcProfileConstants.ID_ATTRIBUTE_PROFILE_ID, getProfileId());
  }

  @Override
  protected String getSubjectKeyInfoAttributeDatatype() {
    return null;
  }

  @Override
  protected String getProfileIdAttributeIdentifer() {
    return OidcProfileConstants.ID_ATTRIBUTE_PROFILE_ID;
  }

  @Override
  protected String getMapUserToPOSIXEnvironmentObligationIdentifier() {
    return null;
  }

  @Override
  protected String getUserIdAttributeAssignmentIdentifier() {
    return null;
  }

  @Override
  protected String getGroupIdAttributeAssignmentIdentifier() {
    return null;
  }

  @Override
  protected String getPrimaryGroupIdAttributeAssignmentIdentifier() {
    return null;
  }

  private Attribute createAttribute(String id, String value) {
    Attribute attr = new Attribute(id);
    attr.getValues().add(value);
    return attr;
  }

}
