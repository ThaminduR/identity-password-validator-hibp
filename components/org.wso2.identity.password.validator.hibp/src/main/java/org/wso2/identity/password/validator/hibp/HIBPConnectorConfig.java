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
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This connector's own configuration, published as a governance connector.
 * <p>
 * Registering this is what gives the connector a per-organization setting surface and a Console presence.
 * Both appear when the bundle is installed and disappear when it is removed, so an administrator is never
 * offered a source the deployment does not have.
 */
public class HIBPConnectorConfig implements IdentityConnectorConfig {

    public static final String CONNECTOR_NAME = "hibp";
    public static final String CATEGORY = "Password Security";

    public static final String ENABLE = "hibp.enable";
    public static final String DENY_ON_FAILURE = "hibp.denyOnFailure";

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
        names.put(ENABLE, "Check passwords against Have I Been Pwned");
        names.put(DENY_ON_FAILURE, "Refuse the password if this service cannot be reached");

        return names;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put(ENABLE, "Refuse passwords that appear in the Have I Been Pwned corpus. Only a "
                + "partial, irreversible fingerprint of the password is sent; the password itself and the "
                + "user's identity never leave this server.");
        descriptions.put(DENY_ON_FAILURE, "Leave this off to let passwords through when the service is "
                + "unreachable. Turn it on only if you would rather block sign-ups and password resets than "
                + "risk accepting a breached password. An API key, if you have one, is configured by your "
                + "deployment team.");

        return descriptions;
    }

    @Override
    public String[] getPropertyNames() {

        return new String[] { ENABLE, DENY_ON_FAILURE };
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties defaults = new Properties();
        // Off until an administrator asks for it.
        defaults.put(ENABLE, "false");
        // A third party's outage should not stop every password change in the deployment.
        defaults.put(DENY_ON_FAILURE, "false");

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
    public Map<String, Property> getMetaData() {

        Map<String, Property> metadata = new LinkedHashMap<>();

        // Both settings are booleans, which is also what makes the Console render them as switches: it
        // picks a toggle when a property's value is "true" or "false", and a text box otherwise.
        Property enable = new Property();
        enable.setType("boolean");
        metadata.put(ENABLE, enable);

        Property denyOnFailure = new Property();
        denyOnFailure.setType("boolean");
        metadata.put(DENY_ON_FAILURE, denyOnFailure);

        return Collections.unmodifiableMap(metadata);
    }
}
