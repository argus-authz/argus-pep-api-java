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
 */

package org.glite.authz.common.model;

import java.io.Serializable;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.util.Strings;

/** A requirement that a particular attribute have a given set of values within the PEP. */
@NotThreadSafe
public final class AttributeAssignment implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -1159499031052230298L;

    /** ID of the attribute. */
    private String attributeId;

    /** Data type of the attribute. */
    private String dataType;

    /** Values of the attribute. */
    private String value;

    /** Constructor. */
    public AttributeAssignment() {
    }

    /**
     * Gets the ID of the attribute.
     * 
     * @return ID of the attribute
     */
    public String getAttributeId() {
        return attributeId;
    }

    /**
     * Sets the ID of the attribute.
     * 
     * @param id ID of the attribute
     */
    public void setAttributeId(String id) {
        attributeId = Strings.safeTrimOrNullString(id);
    }

    /**
     * Gets the data type of the attribute.
     * 
     * @return data type of the attribute
     */
    public String getDataType() {
        return dataType;
    }

    /**
     * Sets the data type of the attribute.
     * 
     * @param type data type of the attribute
     */
    public void setDataType(String type) {
        dataType = Strings.safeTrimOrNullString(type);
    }

    /**
     * Gets the value the identified attribute must be assigned.
     * 
     * @return value the identified attribute must be assigned
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the value the identified attribute must be assigned.
     * 
     * @param newValue value the identified attribute must be assigned
     */
    public void setValue(String newValue) {
        value = Strings.safeTrimOrNullString(newValue);
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append("AttributeAssignment {");
        stringBuilder.append("attributeId: ").append(attributeId).append(", ");
        stringBuilder.append("dataType: ").append(dataType).append(", ");
        stringBuilder.append("value: ").append(value).append(", ");
        stringBuilder.append("}");

        return stringBuilder.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;

        hash = 31 * hash + (null == attributeId ? 0 : attributeId.hashCode());
        hash = 31 * hash + (null == dataType ? 0 : dataType.hashCode());
        hash = 31 * hash + (null == value ? 0 : value.hashCode());

        return hash;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }

        AttributeAssignment otherAssignment = (AttributeAssignment) obj;
        return Strings.safeEquals(attributeId, otherAssignment)
                && Strings.safeEquals(dataType, otherAssignment.getDataType())
                && Strings.safeEquals(value, otherAssignment.getValue());
    }
}