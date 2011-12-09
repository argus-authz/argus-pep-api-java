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
package org.glite.authz.common.profile;

import org.glite.authz.common.model.Attribute;

/**
 * XACML namespaces and identifiers constants for the EMI <a
 * href="http://dci-sec.org/xacml/profile/common-authz/1.1">Common XACML
 * Authorization Profile v.1.1</a>
 */
public class CommonXACMLAuthorizationProfileConstants {

    /** Namespaces, datatypes and identifiers name components separator */
    protected static final char SEPARATOR= '/';

    /** The namespace base prefix {@value} */
    protected static final String NS_PREFIX= "http://dci-sec.org/xacml";

    /** The attribute namespace: {@value} . */
    public static final String NS_ATTRIBUTE= NS_PREFIX + SEPARATOR
            + "attribute";

    /** The action namespace: {@value} */
    public static final String NS_ACTION= NS_PREFIX + SEPARATOR + "action";

    /** The profile namespace: {@value} */
    public static final String NS_PROFILE= NS_PREFIX + SEPARATOR + "profile";

    /** The obligation namespace: {@value} */
    public static final String NS_OBLIGATION= NS_PREFIX + SEPARATOR
            + "obligation";

    /** The attribute id profile-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_PROFILE_ID= NS_ATTRIBUTE
            + SEPARATOR + "profile-id";

    /** The attribute id subject-issuer identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_ISSUER= NS_ATTRIBUTE
            + SEPARATOR + "subject-issuer";

    /** The attribute id subject-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_ID= Attribute.ID_SUB_ID;

    /** The attribute id subject key-info identifier: {@value} */
    public static final String ID_ATTRIBUTE_SUBJECT_KEY_INFO= Attribute.ID_SUB_KEY_INFO;

    /** The attribute id virtual-organization identifier: {@value} */
    public static final String ID_ATTRIBUTE_VIRTUAL_ORGANIZATION= NS_ATTRIBUTE
            + SEPARATOR + "virtual-organization";

    /** The attribute id group identifier: {@value} */
    public static final String ID_ATTRIBUTE_GROUP= NS_ATTRIBUTE + SEPARATOR
            + "group";

    /** The attribute id primary group identifier: {@value} */
    public static final String ID_ATTRIBUTE_PRIMARY_GROUP= ID_ATTRIBUTE_GROUP
            + SEPARATOR + "primary";

    /** The attribute id role identifier: {@value} */
    public static final String ID_ATTRIBUTE_ROLE= NS_ATTRIBUTE + SEPARATOR
            + "role";

    /** The attribute id primary role identifier: {@value} */
    public static final String ID_ATTRIBUTE_PRIMARY_ROLE= ID_ATTRIBUTE_ROLE
            + SEPARATOR + "primary";

    /** The attribute id resource-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_RESOURCE_ID= Attribute.ID_RES_ID;

    /** The attribute id resource owner identifier: {@value} */
    public static final String ID_ATTRIBUTE_RESOURCE_OWNER= NS_ATTRIBUTE
            + SEPARATOR + "resource-owner";

    /** The attribute id action-id identifier: {@value} */
    public static final String ID_ATTRIBUTE_ACTION_ID= Attribute.ID_ACT_ID;

    /** The attribute id user-id (user name) identifier: {@value} */
    public static final String ID_ATTRIBUTE_USER_ID= NS_ATTRIBUTE + SEPARATOR
            + "user-id";

    /** The attribute id group-id (user group name) identifier: {@value} */
    public static final String ID_ATTRIBUTE_GROUP_ID= NS_ATTRIBUTE + SEPARATOR
            + "group-id";

    /**
     * The attribute id primary group-id (user group name) identifier: {@value}
     */
    public static final String ID_ATTRIBUTE_PRIMARY_GROUP_ID= ID_ATTRIBUTE_GROUP_ID
            + SEPARATOR + "primary";

    /** The obligation id map user to local environment identifier: {@value} */
    public static final String ID_OBLIGATION_MAP_LOCAL_USER= NS_OBLIGATION
            + SEPARATOR + "map-local-user";

    /** The obligation id map user to POSIX environment identifier: {@value} */
    public static final String ID_OBLIGATION_MAP_POSIX_USER= ID_OBLIGATION_MAP_LOCAL_USER
            + SEPARATOR + "posix";

    /** The datatype #anyURI: {@value} */
    public static final String DATATYPE_ANY_URI= Attribute.DT_ANY_URI;

    /** The datatype #string: {@value} */
    public static final String DATATYPE_STRING= Attribute.DT_STRING;

    /** The datatype X.500 name (RFC2253 format DN): {@value} */
    public static final String DATATYPE_X500_NAME= Attribute.DT_X500_NAME;

    /** The datatype base64 encoded binary: {@value} */
    public static final String DATATYPE_BASE64_BINARY= Attribute.DT_BASE64_BINARY;

    /** Common XACML Authorization Profile version: {@value} */
    public static final String COMMON_XACML_AUTHZ_V1_1_PROFILE_VERSION= "1.1";

    /** Common XACML Authorization Profile identifier: {@value} */
    public static final String COMMON_XACML_AUTHZ_V1_1_PROFILE_ID= NS_PROFILE
            + SEPARATOR + "common-authz" + SEPARATOR
            + COMMON_XACML_AUTHZ_V1_1_PROFILE_VERSION;

}
