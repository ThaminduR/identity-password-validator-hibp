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
 * This connector's own configuration, published as a governance connector.
 * <p>
 * Registering this is what gives the connector a per-organization setting surface and a Console presence.
 * Both appear when the bundle is installed and disappear when it is removed, so an administrator is never
 * offered a source the deployment does not have.
 */
public class HIBPConnectorConfig implements IdentityConnectorConfig {

    /**
     * Deliberately not "hibp", and not a prefix of any property name below.
     * <p>
     * When a connector's name is a prefix of its property names, the management API stops honouring the
     * declared property order: it collects every same-prefixed property on the first pass, in the arbitrary
     * order the platform's property map yields. Keeping the name distinct from the property namespace means
     * each property is matched on its own pass, and {@link #getPropertyNames()} decides what an administrator
     * sees first.
     */
    public static final String CONNECTOR_NAME = "have-i-been-pwned";
    public static final String CATEGORY = "Password Security";

    /**
     * The {@code __secret__} prefix is the platform's marker for a credential in connector configuration.
     * It is what makes the Console render this as a password field rather than a plain text box, and it is
     * the same convention the shipped Sift and ELK connectors use for their own keys.
     */
    public static final String API_KEY = "__secret__hibp.apiKey";

    /**
     * What the API key holds when there is no key to hold.
     * <p>
     * The Console's generic connector form marks every text field {@code required}, with no way for a
     * connector to say otherwise, so an empty API key makes the browser refuse to submit the form - and an
     * administrator with no key could not change the switches either. A default that is never empty keeps
     * the form usable. {@link #NO_API_KEY} is treated as absent everywhere the key is read.
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
        // hint that wraps runs up against the switch on the right and reads as though it belongs to the text
        // rather than to the setting. Every shipped connector keeps these to a single line; the longer
        // explanations live in the connector's documentation.
        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put(ENABLE, "Refuse passwords found in the Have I Been Pwned breach corpus.");
        descriptions.put(API_KEY, "Optional. Leave this as \"none\" if you do not have a key.");
        descriptions.put(REFUSE_WHEN_UNREACHABLE, "Block password changes while the service is unreachable.");

        return descriptions;
    }

    @Override
    public String[] getPropertyNames() {

        // This is the order the Console renders. See CONNECTOR_NAME for why it is honoured at all.
        return new String[] { ENABLE, API_KEY, REFUSE_WHEN_UNREACHABLE };
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties defaults = new Properties();
        // Not empty: see NO_API_KEY. The range endpoint is unauthenticated, and a missing key must never be
        // read as a reason to stop checking.
        defaults.put(API_KEY, NO_API_KEY);
        // Off until an administrator asks for it.
        defaults.put(ENABLE, "false");
        // A third party's outage should not stop every password change in the deployment.
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

        // A boolean is also what makes the Console render a switch: it picks a toggle when a property's
        // value is "true" or "false", and a text box otherwise.
        Property enable = new Property();
        enable.setType(IdentityMgtConstants.DataTypes.BOOLEAN.getValue());
        metadata.put(ENABLE, enable);

        Property refuseWhenUnreachable = new Property();
        refuseWhenUnreachable.setType(IdentityMgtConstants.DataTypes.BOOLEAN.getValue());
        metadata.put(REFUSE_WHEN_UNREACHABLE, refuseWhenUnreachable);

        return Collections.unmodifiableMap(metadata);
    }
}
