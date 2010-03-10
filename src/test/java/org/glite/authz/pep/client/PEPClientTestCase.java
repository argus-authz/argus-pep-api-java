/*
 * Copyright (c) 2010. Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
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
package org.glite.authz.pep.client;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;

import junit.framework.TestCase;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.client.config.PEPClientConfiguration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * PEPClientTestCase
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 * @version $Revision$
 */
public class PEPClientTestCase extends TestCase {

    private Log log= LogFactory.getLog(PEPClientTestCase.class);

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test method for
     * {@link org.glite.authz.pep.client.PEPClient#PEPClient(org.glite.authz.pep.client.config.PEPClientConfiguration)}
     * .
     * 
     * @throws IOException
     * @throws AuthorizationServiceException
     * @throws GeneralSecurityException
     * @throws CertificateException
     */
    public void testPEPClient() throws IOException,
            AuthorizationServiceException, GeneralSecurityException {
        PEPClientConfiguration config= new PEPClientConfiguration();
        String endpoint= "https://chaos.switch.ch:8154/authz";
        config.addPEPDaemonEndpoint(endpoint);
        
        String cadir= "/etc/grid-security/certificates";
        String home= System.getProperty("user.home");
        String dotGlobus= home + File.separator + ".globus";
        String usercert= dotGlobus + File.separator + "usercert.pem";
        String userkey= dotGlobus + File.separator + "userkey.pem";
        String password= "changeit";
        
        config.setTrustMaterial(cadir);
        config.setKeyMaterial(usercert,userkey,password);
        PEPClient client= new PEPClient(config);
        Request request= createRequest("/Users/tschopp/.globus/usercert.pem",
                                       "gridftp",
                                       "access");
        System.out.println(request);
        Response response= client.authorize(request);
        System.out.println(response);
    }

    static protected Request createRequest(String usercertFilename,
            String resourceid, String actionid) throws IOException {
        Request request= new Request();
        // resource
        Resource resource= new Resource();
        Attribute attrResourceId= new Attribute();
        attrResourceId.setId(Attribute.ID_RES_ID);
        attrResourceId.setDataType(Attribute.DT_STRING);
        attrResourceId.getValues().add(resourceid);
        resource.getAttributes().add(attrResourceId);
        request.getResources().add(resource);
        // action
        Action action= new Action();
        Attribute attrActionId= new Attribute();
        attrActionId.setId(Attribute.ID_ACT_ID);
        attrActionId.setDataType(Attribute.DT_STRING);
        attrActionId.getValues().add(actionid);
        action.getAttributes().add(attrActionId);
        request.setAction(action);
        // subject
        Subject subject= new Subject();
        Attribute attrKeyInfo= new Attribute();
        attrKeyInfo.setId(Attribute.ID_SUB_KEY_INFO);
        attrKeyInfo.setDataType(Attribute.DT_STRING);
        File file= new File(usercertFilename);
        FileInputStream fis= new FileInputStream(file);
        BufferedInputStream bis= new BufferedInputStream(fis);
        byte[] bytes= new byte[(int) file.length()];
        bis.read(bytes);
        String keyInfo= new String(bytes);
        attrKeyInfo.getValues().add(keyInfo);
        subject.getAttributes().add(attrKeyInfo);
        request.getSubjects().add(subject);
        // profile id -> environment
        Environment environment= new Environment();
        Attribute attrProfileId= new Attribute();
        attrProfileId.setId(Attribute.ID_ENV_PROFILE_ID);
        attrProfileId.setDataType(Attribute.DT_ANY_URI);
        attrProfileId.getValues().add("http://glite.org/xacml/profile/grid-wn/1.0");
        environment.getAttributes().add(attrProfileId);
        request.setEnvironment(environment);
        return request;
    }

}
