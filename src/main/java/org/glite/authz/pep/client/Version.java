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

/**
 * Version to retrieve version info from the jar manifest.
 * 
 * @author Valery Tschopp &lt;tschopp&#64;switch.ch&gt;
 */
public class Version {
    static final String COPYRIGHT= "Copyright (c) 2010 Members of the EGEE Collaboration";

    static final Package PKG= Version.class.getPackage();

    /**
     * @return the copyright string
     */
    static public String getCopyright() {
        return COPYRIGHT;
    }

    /**
     * Returns the implementation version from the jar MANIFEST.
     * 
     * @return the implementation version
     */
    static public String getVersion() {
        return PKG.getImplementationVersion();
    }

    /**
     * Returns the implementation title from the jar MANIFEST.
     * 
     * @return the implementation title
     */
    static public String getName() {
        return PKG.getImplementationTitle();
    }

    /**
     * Returns the specification title from the jar MANIFEST.
     * 
     * @return the specification title
     */
    static public String getDescription() {
        return PKG.getSpecificationTitle();
    }

    /**
     * Prevents instantiation.
     */
    private Version() {
    }

}
