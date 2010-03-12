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

import java.security.cert.X509Certificate;
import java.util.List;

import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;
import org.glite.authz.common.profile.GridWNAuthorizationProfile;
import org.glite.authz.common.security.PEMFileReader;
import org.glite.authz.pep.client.PEPClient;
import org.glite.authz.pep.client.config.PEPClientConfiguration;

/**
 * Simple example to use the Argus PEP Java client, authorize a request and
 * parse the response.
 */
public class ArgusPEPClientExample {

    public static void main(String[] args) throws Exception {

        // Argus PEP daemon endpoint
        String endpoint= "https://chaos.switch.ch:8154/authz";

        // trust and key material for the HTTPS/TLS communication
        // with the Argus PEP daemon
        String cadirname= "/etc/grid-security/certificates";
        String clientcert= "/etc/grid-security/hostcert.pem";
        String clientkey= "/etc/grid-security/hostkey.pem";

        // create PEP client config
        PEPClientConfiguration config= new PEPClientConfiguration();
        config.addPEPDaemonEndpoint(endpoint);
        config.setTrustMaterial(cadirname);
        config.setKeyMaterial(clientcert, clientkey, "changeit");

        // create the PEP client
        PEPClient pep= new PEPClient(config);

        // get the user proxy
        String userproxy= "/tmp/x509up_u959";
        PEMFileReader reader= new PEMFileReader();
        X509Certificate[] certs= reader.readCertificates(userproxy);
        // create a request
        String resourceid= "gridftp";
        String actionid= "access";
        Request request= GridWNAuthorizationProfile.createRequest(certs,
                                                                  resourceid,
                                                                  actionid);
        System.out.println(request);

        // authorize the request by PEP daemon
        Response response= pep.authorize(request);
        System.out.println(response);

        // parse the response
        List<Result> results= response.getResults();
        for (Result result : results) {
            System.out.println("Decison: " + result.getDecisionString());
            int decision= result.getDecision();
            if (decision == Result.DECISION_PERMIT) {
                List<Obligation> obligations= result.getObligations();
                for (Obligation obligation : obligations) {
                    String id= obligation.getId();
                    System.out.println("ObligationId: " + id);
                    int fulfillOn= obligation.getFulfillOn();
                    if (fulfillOn == decision) {
                        List<AttributeAssignment> attributeAssignments= obligation.getAttributeAssignments();
                        for (AttributeAssignment attributeAssignment : attributeAssignments) {
                            System.out.println("AttributeAssignmentId: "
                                    + attributeAssignment.getAttributeId());
                            String value= attributeAssignment.getValue();
                            System.out.println("Value: " + value);
                        }
                    }
                }
            }
            else {
                Status status= result.getStatus();
                if (status.getMessage()!=null) {
                    System.out.println("Status: " + status.getMessage());
                }
                StatusCode statusCode= status.getCode();
                if (statusCode.getCode()!=null) {
                    System.out.println("StatusCode: " + statusCode.getCode());
                }
                
            }
        }
    }
}
