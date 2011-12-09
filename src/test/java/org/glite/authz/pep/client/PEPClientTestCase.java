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
package org.glite.authz.pep.client;

import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import junit.framework.TestCase;

import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.security.PEMFileReader;
import org.glite.authz.pep.client.PEPClient;
import org.glite.authz.pep.client.config.PEPClientConfiguration;
import org.glite.authz.pep.profile.AuthorizationProfile;
import org.glite.authz.pep.profile.GridWNAuthorizationProfile;

/**
 * PEPClientTestCase
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 * @version $Revision$
 */
public class PEPClientTestCase extends TestCase {

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
     * @throws Exception
     * 
     * @throws CertificateException
     */
    public void testGridWNAuthorizationProfile() throws Exception {
        PEPClientConfiguration config= new PEPClientConfiguration();
        String endpoint= "https://chaos.switch.ch:8154/authz";
        String resourceid= "switch";
        String actionid= "switch";
        config.addPEPDaemonEndpoint(endpoint);

        String cadir= "/etc/grid-security/certificates";
        String home= System.getProperty("user.home");
        String dotGlobus= home + File.separator + ".globus";
        String usercert= dotGlobus + File.separator + "usercert.pem";
        String userkey= dotGlobus + File.separator + "userkey.pem";
        String password= "1absynth";

        config.setTrustMaterial(cadir);
        config.setKeyMaterial(usercert, userkey, password);
        PEPClient client= new PEPClient(config);
        PEMFileReader reader= new PEMFileReader();
        X509Certificate[] certs= reader.readCertificates(usercert);
        
        AuthorizationProfile profile= GridWNAuthorizationProfile.getInstance();
        Request request= profile.createRequest(certs, resourceid, actionid);
        System.out.println("----------------------------------------");
        System.out.println(request);
        System.out.println("----------------------------------------");
        Response response= client.authorize(request);
        System.out.println("----------------------------------------");
        System.out.println(response);
        System.out.println("----------------------------------------");
        Obligation obligation= profile.getObligationPosixMapping(response);
        String username= profile.getAttributeAssignmentUserId(obligation);
        System.out.println("Username: " + username);
        String group= profile.getAttributeAssignmentPrimaryGroupId(obligation);
        System.out.println("Group: " + group);
        List<String> groups= profile.getAttributeAssignmentGroupIds(obligation);
        System.out.println("Secondary Groups: " + groups);
    }

}
