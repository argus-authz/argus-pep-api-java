/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.obligation.dfpmap;

/**
 * A function that determines if a particular candidate is a match to {@link DFPM} key.
 * 
 * @param <CandidateType> type of keys being checked
 */
public interface DFPMMatchStrategy<CandidateType> {

    /**
     * Determines if a candidate is a match to a {@link DFPM} key.
     * 
     * @param dfpmKey the {@link DFPM} key
     * @param candidate the possible match candidate
     * 
     * @return true if the candidate is a match, false if not
     */
    public boolean isMatch(String dfpmKey, CandidateType candidate);
}