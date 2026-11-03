/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * The governance connector the Console renders and the management API serves.
 */
public class HIBPConnectorConfigTest {

    private static final String TENANT = "carbon.super";

    private final HIBPConnectorConfig config = new HIBPConnectorConfig();

    @Test
    public void itIsPublishedUnderPasswordSecurity() {

        assertEquals(config.getName(), "have-i-been-pwned");
        assertEquals(config.getFriendlyName(), "Have I Been Pwned");
        assertEquals(config.getCategory(), "Password Security");
        assertEquals(config.getSubCategory(), "DEFAULT");
    }

    /** The Console renders the properties in this order. */
    @Test
    public void itPublishesTheTwoSwitchesInOrder() {

        assertEquals(config.getPropertyNames(),
                new String[] { HIBPConnectorConfig.ENABLE, HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE });
    }

    /**
     * A connector name that prefixes its property names makes the management API emit them in arbitrary
     * order, so {@link HIBPConnectorConfig#getPropertyNames()} would stop deciding it.
     */
    @Test
    public void theConnectorNameIsOutsideThePropertyNamespace() {

        for (String name : config.getPropertyNames()) {
            assertFalse(name.startsWith(config.getName()), name);
        }
    }

    /** The range endpoint needs no credential, so nothing secret is stored in or returned by the API. */
    @Test
    public void noCredentialIsHeldInTheGovernanceStore() {

        for (String name : config.getPropertyNames()) {
            assertFalse(name.toLowerCase(Locale.ROOT).contains("key"), name);
            assertFalse(name.startsWith("__secret__"), name);
        }
        assertTrue(config.getConfidentialPropertyValues(TENANT).isEmpty());
    }

    /** Installing the bundle changes nothing until an organization opts in, and an outage refuses by default. */
    @Test
    public void theSourceIsOffAndAnOutageRefusesByDefault() throws Exception {

        Properties defaults = config.getDefaultPropertyValues(TENANT);
        assertEquals(defaults.size(), 2);
        assertEquals(defaults.get(HIBPConnectorConfig.ENABLE), "false");
        assertEquals(defaults.get(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE), "true");
    }

    @Test
    public void defaultsForNamedPropertiesLeaveOutAnythingUnrecognised() throws Exception {

        Map<String, String> defaults = config.getDefaultPropertyValues(
                new String[] { HIBPConnectorConfig.ENABLE, "unknown.property" }, TENANT);
        assertEquals(defaults.size(), 1);
        assertEquals(defaults.get(HIBPConnectorConfig.ENABLE), "false");
    }

    /** Every published property has a label, a hint and a type, so the Console renders each one fully. */
    @Test
    public void everyPropertyIsLabelledDescribedAndTyped() {

        Map<String, String> labels = config.getPropertyNameMapping();
        Map<String, String> hints = config.getPropertyDescriptionMapping();
        Map<String, Property> metadata = config.getMetaData();
        for (String name : config.getPropertyNames()) {
            assertTrue(labels.containsKey(name), "label for " + name);
            assertTrue(hints.containsKey(name), "hint for " + name);
            assertTrue(metadata.containsKey(name), "type for " + name);
        }
        assertEquals(labels.keySet(), metadata.keySet());
        assertEquals(hints.size(), config.getPropertyNames().length);
    }

    /** A boolean renders as a switch. Anything else would make an administrator type the value by hand. */
    @Test
    public void bothSwitchesAreTypedAsBooleans() {

        String bool = IdentityMgtConstants.DataTypes.BOOLEAN.getValue();
        Arrays.stream(config.getPropertyNames()).forEach(name ->
                assertEquals(config.getMetaData().get(name).getType(), bool, name));
    }
}
