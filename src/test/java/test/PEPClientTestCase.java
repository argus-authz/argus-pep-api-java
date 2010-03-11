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
package test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.GridWNAuthorizationProfile;
import org.glite.authz.common.security.PEMFileReader;
import org.glite.authz.pep.client.PEPClient;
import org.glite.authz.pep.client.Version;
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
        String userproxy= dotGlobus + File.separator + "userproxy.pem";
        String password= "changeit";

        config.setTrustMaterial(cadir);
        config.setKeyMaterial(userproxy, userproxy, password);
        PEPClient client= new PEPClient(config);
        PEMFileReader reader= new PEMFileReader();
        X509Certificate[] certs= reader.readCertificates(userproxy);
        Request request= createRequest(certs, "gridftp", "access");
        System.out.println(request);
        Response response= client.authorize(request);
        System.out.println(response);
    }

    static protected Request createRequest(X509Certificate [] certs,
            String resourceid, String actionid) throws IOException {
        Subject subject= GridWNAuthorizationProfile.createSubject(certs);
        Resource resource= GridWNAuthorizationProfile.createResource(resourceid);
        Action action= GridWNAuthorizationProfile.createAction(actionid);
        Request request= GridWNAuthorizationProfile.createRequest(subject,
                                                                  resource,
                                                                  action);
        return request;
    }

}
