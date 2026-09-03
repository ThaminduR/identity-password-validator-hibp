/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.password.validator.hibp;

import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * This connector's own configuration, published as a governance connector. It gives the connector a
 * per-organization set of settings and a Console presence. Both appear when the bundle is deployed and are
 * removed when it is removed.
 */
public class HIBPConnectorConfig implements IdentityConnectorConfig {

    /**
     * This is not "hibp", and it is not a prefix of any property name below. When the connector name is a
     * prefix of its property names, the management API collects them in one pass in arbitrary map order, and
     * {@link #getPropertyNames()} no longer decides the order the Console renders.
     */
    public static final String CONNECTOR_NAME = "have-i-been-pwned";
    public static final String CATEGORY = "Password Security";

    /**
     * The {@code __secret__} prefix is the platform's marker for a credential in connector configuration.
     * It makes the Console render this property as a password field instead of a plain text box. The shipped
     * Sift and ELK connectors use the same convention for their keys.
     */
    public static final String API_KEY = "__secret__hibp.apiKey";

    /**
     * The value the API key property holds when no key is set. The Console's generic form marks every text
     * field as required, so an empty value blocks submission of the whole form. This value is treated as
     * absent wherever the key is read.
     */
    public static final String NO_API_KEY = "none";
    public static final String ENABLE = "hibp.enable";
    public static final String REFUSE_WHEN_UNREACHABLE = "hibp.refuseWhenUnreachable";

    @Override
    public String getName() {

        return CONNECTOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return "Have I Been Pwned";
    }

    @Override
    public String getCategory() {

        return CATEGORY;
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> names = new LinkedHashMap<>();
        names.put(API_KEY, "API key");
        names.put(ENABLE, "Enable");
        names.put(REFUSE_WHEN_UNREACHABLE, "Refuse the password if this service cannot be reached");

        return names;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        // One short line each. The Console gives a property's hint the full width of the label column, so a
        // hint that wraps runs into the switch on the right and appears to belong to the next property.
        // Every shipped connector keeps these to a single line and puts longer explanations in its
        // documentation.
        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put(ENABLE, "Refuse passwords found in the Have I Been Pwned breach corpus.");
        descriptions.put(API_KEY, "Optional. Leave this as \"none\" if you do not have a key.");
        descriptions.put(REFUSE_WHEN_UNREACHABLE, "Block password changes while the service is unreachable.");

        return descriptions;
    }

    @Override
    public String[] getPropertyNames() {

        // This is the order the Console renders. See CONNECTOR_NAME for the condition that makes it apply.
        return new String[] { ENABLE, API_KEY, REFUSE_WHEN_UNREACHABLE };
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties defaults = new Properties();
        // Not empty. See NO_API_KEY. The range endpoint does not require authentication, so a missing key
        // must not stop the check.
        defaults.put(API_KEY, NO_API_KEY);
        // Off until an administrator enables it.
        defaults.put(ENABLE, "false");
        // Default to allowing, so that a third party's outage does not stop every password change.
        defaults.put(REFUSE_WHEN_UNREACHABLE, "false");

        return defaults;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        Map<String, String> defaults = new HashMap<>();
        Properties all = getDefaultPropertyValues(tenantDomain);
        for (String name : propertyNames) {
            Object value = all.get(name);
            if (value != null) {
                defaults.put(name, String.valueOf(value));
            }
        }

        return defaults;
    }

    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        return Collections.singletonList(API_KEY);
    }

    @Override
    public Map<String, Property> getMetaData() {

        Map<String, Property> metadata = new LinkedHashMap<>();

        Property apiKey = new Property();
        apiKey.setType(IdentityMgtConstants.DataTypes.STRING.getValue());
        metadata.put(API_KEY, apiKey);

        // The type also decides the control the Console renders. It shows a toggle when a property's value
        // is "true" or "false", and a text box otherwise.
        Property enable = new Property();
        enable.setType(IdentityMgtConstants.DataTypes.BOOLEAN.getValue());
        metadata.put(ENABLE, enable);

        Property refuseWhenUnreachable = new Property();
        refuseWhenUnreachable.setType(IdentityMgtConstants.DataTypes.BOOLEAN.getValue());
        metadata.put(REFUSE_WHEN_UNREACHABLE, refuseWhenUnreachable);

        return Collections.unmodifiableMap(metadata);
    }
}
