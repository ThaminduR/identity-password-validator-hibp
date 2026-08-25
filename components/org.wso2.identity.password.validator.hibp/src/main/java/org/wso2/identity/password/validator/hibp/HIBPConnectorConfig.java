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

import java.util.ArrayList;
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

    public static final String CONNECTOR_NAME = "hibp";
    public static final String CATEGORY = "Password Security";

    public static final String ENABLE = "hibp.enable";
    public static final String API_KEY = "hibp.apiKey";
    public static final String ON_ERROR = "hibp.onError";

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
        names.put(API_KEY, "API key");
        names.put(ON_ERROR, "If Have I Been Pwned cannot be reached");

        return names;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptions = new LinkedHashMap<>();
        descriptions.put(ENABLE, "Refuse passwords that appear in the Have I Been Pwned corpus. Only a "
                + "partial, irreversible fingerprint of the password is sent; the password itself and the "
                + "user's identity never leave this server.");
        descriptions.put(API_KEY, "Optional. The range endpoint needs no authentication, and leaving this "
                + "empty does not stop passwords being checked.");
        descriptions.put(ON_ERROR, "Whether to allow or deny a password when this service cannot answer. "
                + "Choose deny only if you would rather block sign-ups than risk accepting a breached "
                + "password.");

        return descriptions;
    }

    @Override
    public String[] getPropertyNames() {

        return new String[] { ENABLE, API_KEY, ON_ERROR };
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        Properties defaults = new Properties();
        // Off until an administrator asks for it.
        defaults.put(ENABLE, "false");
        defaults.put(API_KEY, "");
        // A third party's outage should not stop every password change in the deployment.
        defaults.put(ON_ERROR, "allow");

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

    /**
     * The API key is a credential, so it is masked in every read of this connector's configuration. The
     * previous version of this extension returned it in cleartext from the governance API.
     */
    @Override
    public List<String> getConfidentialPropertyValues(String tenantDomain) {

        List<String> confidential = new ArrayList<>();
        confidential.add(API_KEY);

        return confidential;
    }

    @Override
    public Map<String, Property> getMetaData() {

        Map<String, Property> metadata = new LinkedHashMap<>();

        Property enable = new Property();
        enable.setType("boolean");
        metadata.put(ENABLE, enable);

        Property onError = new Property();
        onError.setType("select");
        onError.setOptions(new String[] { "allow", "deny" });
        metadata.put(ON_ERROR, onError);

        Property apiKey = new Property();
        apiKey.setType("password");
        apiKey.setConfidential(true);
        metadata.put(API_KEY, apiKey);

        return Collections.unmodifiableMap(metadata);
    }
}
