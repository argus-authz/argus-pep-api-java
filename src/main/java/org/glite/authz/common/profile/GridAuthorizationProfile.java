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
package org.glite.authz.common.profile;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Resource;

/**
 * Abstract Grid authorization profile base class.
 * 
 * Defines the namespaces and attribute used in grid WN and CE authorization
 * profiles.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public abstract class GridAuthorizationProfile extends GenericProfile {

    /** The namespace base prefix {@value} */
    private static final String NS_PREFIX= "http://glite.org/xacml";

    /** The attribute namespace: {@value} . */
    public static final String NS_ATTRIBUTE= NS_PREFIX + "/attribute";

    /** The action namespace: {@value} . */
    public static final String NS_ACTION= NS_PREFIX + "/action";

    /** The datatype namespace: {@value} . */
    public static final String NS_DATATYPE= NS_PREFIX + "/datatype";

    /** The profile namespace: {@value} . */
    public static final String NS_PROFILE= NS_PREFIX + "/profile";

    /** The obligation namespace: {@value} . */
    public static final String NS_OBLIGATION= NS_PREFIX + "/obligation";

    /** The algorithm namespace: {@value} . */
    public static final String NS_ALGORITHM= NS_PREFIX + "/algorithm";

    /** The attribute id profile-id identifier, {@value} . */
    public static final String ID_ATTRIBUTE_PROFILE_ID= NS_ATTRIBUTE
            + "/profile-id";
    
    /**
     * Creates a {@link Resource} containing the {@link Attribute}
     * {@value org.glite.authz.common.model.Attribute#ID_RES_ID} with the value
     * given as parameter.
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
     * Creates an {@link Action} containing the {@link Attribute}
     * {@value org.glite.authz.common.model.Attribute#ID_ACT_ID} with the value
     * given as parameter.
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
     * Default constructor
     */
    protected GridAuthorizationProfile() {
        super();
    }
}
