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
package example;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.security.PEMFileReader;
import org.glite.authz.pep.client.PEPClient;
import org.glite.authz.pep.client.PEPClientException;
import org.glite.authz.pep.client.config.PEPClientConfiguration;
import org.glite.authz.pep.client.config.PEPClientConfigurationException;
import org.glite.authz.pep.profile.AuthorizationProfile;
import org.glite.authz.pep.profile.GridWNAuthorizationProfile;
import org.glite.authz.pep.profile.ProfileException;

/**
 * Simple example to use the Argus PEP Java client, authorize a request and
 * parse the response.
 */
public class ArgusPEPClientExample {

    public static void main(String[] args) {

        // Argus PEP daemon endpoint
        String endpoint= "https://chaos.switch.ch:8154/authz";

        // trust and key material for the HTTPS/TLS communication
        // with the Argus PEP daemon
        String cadirname= "/etc/grid-security/certificates";
        String clientcert= "/etc/grid-security/hostcert.pem";
        String clientkey= "/etc/grid-security/hostkey.pem";
        String clientpasswd= "changeit";

        // create PEP client config
        PEPClientConfiguration config= new PEPClientConfiguration();
        try {
            config.addPEPDaemonEndpoint(endpoint);
            config.setTrustMaterial(cadirname);
            config.setKeyMaterial(clientcert, clientkey, clientpasswd);
        } catch (PEPClientConfigurationException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
        // create the PEP client
        PEPClient pep= null;
        try {
            pep= new PEPClient(config);
        } catch (PEPClientException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }

        // get the user proxy
        String userproxy= "/tmp/x509up_u959";
        PEMFileReader reader= new PEMFileReader();
        X509Certificate[] certs= null;
        try {
            certs= reader.readCertificates(userproxy);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }

        // get the profile
        AuthorizationProfile profile= GridWNAuthorizationProfile.getInstance();

        // create a request
        String resourceid= "http://grid.switch.ch/wn002";
        String actionid= GridWNAuthorizationProfile.ACTION_EXECUTE;
        Request request= null;
        try {
            request= profile.createRequest(certs, resourceid, actionid);
        } catch (ProfileException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
        System.out.println(request);

        // authorize the request by PEP daemon
        Response response= null;
        try {
            response= pep.authorize(request);
        } catch (PEPClientException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
        System.out.println(response);

        // extract response attributes
        String userId= null;
        String groupId= null;
        List<String> groupIds= null;
        try {
            Obligation posixMappingObligation= profile.getObligationPosixMapping(response);
            userId= profile.getAttributeAssignmentUserId(posixMappingObligation);
            groupId= profile.getAttributeAssignmentPrimaryGroupId(posixMappingObligation);
            groupIds= profile.getAttributeAssignmentGroupIds(posixMappingObligation);

        } catch (ProfileException e) {
            System.err.println(e);
            // e.printStackTrace();
            System.exit(-1);
        }

        System.out.println("Username: " + userId);
        if (groupId != null) {
            System.out.println("Group: " + groupId);
        }
        if (groupIds != null && !groupIds.isEmpty()) {
            System.out.println("Secondary groups: " + groupIds);
        }
    }
}
