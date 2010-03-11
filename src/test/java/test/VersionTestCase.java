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
package test;

import org.glite.authz.pep.client.Version;

import junit.framework.TestCase;

/** 
 * VersionTestCase
 *
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 * @version $Revision$
 */
public class VersionTestCase extends TestCase {

    public void testVersion() {
        String version= Version.getVersion();
        assertNotNull("Version not set", version);
        String name= Version.getName();
        assertNotNull("Name not set", name);
    }
    
}
