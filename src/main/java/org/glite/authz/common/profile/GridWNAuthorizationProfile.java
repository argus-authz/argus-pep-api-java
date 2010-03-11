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
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;

import org.bouncycastle.openssl.PEMWriter;

/**
 * XACML Grid Worker Node Authorization Profile v1.0.
 * 
 * @see http://edms.cern.ch/document/1058175
 * 
 * @version 1.0
 */
public class GridWNAuthorizationProfile extends GenericProfile {

    /** Version of the profile: {@value} */
    public static final String PROFILE_VERSION= "1.0";

    /** Identifier of the profile: {@value} */
    public static final String PROFILE_ID= "http://glite.org/xacml/profile/grid-wn/1.0";

    /**
     * Creates a {@link Subject} containing the {@link Attribute} identified by
     * {@link Attribute#ID_SUB_KEY_INFO} and for value the certificates given as
     * parameter, encoded in PEM blocks.
     * 
     * @param cert
     *            the user certificate
     * @return the subject
     * @throws IOException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate cert)
            throws IOException {
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
     * @throws IOException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate[] certs)
            throws IOException {
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
     * @throws IOException
     *             if an error occurs while converting a certificate in PEM
     *             format
     */
    public static Subject createSubject(X509Certificate cert,
            X509Certificate[] chain) throws IOException {
        List<X509Certificate> certs= new ArrayList<X509Certificate>();
        if (cert != null) {
            certs.add(cert);
        }
        if (chain != null) {
            for (X509Certificate chainCert : chain) {
                certs.add(chainCert);
            }
        }
        String keyInfo= certificatesToPEMString(certs);
        Subject subject= new Subject();
        Attribute attrKeyInfo= new Attribute();
        attrKeyInfo.setId(Attribute.ID_SUB_KEY_INFO);
        attrKeyInfo.setDataType(Attribute.DT_STRING);
        attrKeyInfo.getValues().add(keyInfo);
        subject.getAttributes().add(attrKeyInfo);
        return subject;
    }

    /**
     * Writes the certificates into a PEM encoded string.
     * 
     * @param certs
     *            List of certificate to PEM encode
     * @return the String containing the PEM encoded certificates
     * @throws IOException
     *             if an error occurs while writing a certificate
     */
    private static String certificatesToPEMString(List<X509Certificate> certs)
            throws IOException {
        StringWriter stringWriter= new StringWriter();
        PEMWriter writer= new PEMWriter(stringWriter);
        for (X509Certificate cert : certs) {
            writer.writeObject(cert);
        }
        try {
            writer.close();
        } catch (Exception e) {
            // ignored
        }
        return stringWriter.toString();
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
     * {@link Attribute#ID_ENV_PROFILE_ID} with value for the Grid WN AuthZ
     * profile identifier.
     * 
     * @return the environment
     */
    public static Environment createEnvironment() {
        Environment environment= new Environment();
        Attribute attrProfileId= new Attribute();
        attrProfileId.setId(Attribute.ID_ENV_PROFILE_ID);
        attrProfileId.setDataType(Attribute.DT_ANY_URI);
        attrProfileId.getValues().add(PROFILE_ID);
        environment.getAttributes().add(attrProfileId);
        return environment;
    }

    /** Prevents instantiation */
    private GridWNAuthorizationProfile() {
    }
}
