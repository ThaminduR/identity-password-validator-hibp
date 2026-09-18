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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.breach.detection.spi.BreachSource;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import java.util.Map;

/**
 * Breach source backed by the Have I Been Pwned range API.
 * <p>
 * The password is never sent. Five characters of its SHA-1 digest go to the service, which returns every
 * suffix sharing that prefix, and the match is made here. This is the reference implementation of the
 * contract.
 */
public class HIBPBreachSource implements BreachSource {

    private static final Log LOG = LogFactory.getLog(HIBPBreachSource.class);

    public static final String SOURCE_ID = "hibp";

    public static final String PROPERTY_API_KEY = "api_key";
    public static final String PROPERTY_BASE_URL = "base_url";
    public static final String PROPERTY_READ_TIMEOUT_MS = "read_timeout_ms";
    public static final String PROPERTY_CONNECT_TIMEOUT_MS = "connect_timeout_ms";
    public static final String PROPERTY_RETRIES = "retries";

    private static final String DEFAULT_BASE_URL = "https://api.pwnedpasswords.com/range/";
    /** Shorter than the platform's 5000 ms action client default, which is not for a per-write call. */
    private static final int DEFAULT_READ_TIMEOUT_MS = 1500;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_RETRIES = 1;

    private volatile String deploymentApiKey;
    private volatile HIBPRangeClient client =
            new HIBPRangeClient(DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS,
                    DEFAULT_RETRIES);

    /**
     * Get the id this source is configured under.
     *
     * @return The source id.
     */
    @Override
    public String getId() {

        return SOURCE_ID;
    }

    /**
     * Get the call order hint. Above an in-process source and below a slower remote one, so an offline list
     * answers first and this connector is only reached for a password that list accepted.
     *
     * @return The priority.
     */
    @Override
    public int getPriority() {

        return 500;
    }

    /**
     * Read the deployment settings. Per-organization policy is not read here. It lives in this connector's
     * governance configuration and is resolved on every call instead.
     *
     * @param configuration Resolved deployment settings for this source.
     */
    @Override
    public void configure(SourceConfiguration configuration) {

        this.client = new HIBPRangeClient(
                configuration.getString(PROPERTY_BASE_URL).orElse(DEFAULT_BASE_URL),
                configuration.getInt(PROPERTY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS),
                configuration.getInt(PROPERTY_READ_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS),
                configuration.getInt(PROPERTY_RETRIES, DEFAULT_RETRIES));

        this.deploymentApiKey = normalizeApiKey(configuration.getString(PROPERTY_API_KEY).orElse(null));

        LOG.info("The Have I Been Pwned connector was configured: endpoint=" + client.getBaseUrl()
                + ", readTimeout=" + client.getReadTimeoutMs() + " ms, apiKey="
                + (deploymentApiKey == null ? "not set" : "set") + ".");
    }

    /**
     * Report whether this organization wants the source consulted. The setting is held in this connector's
     * own governance configuration, which is what the Console edits. A store that cannot be read reports
     * false, so the source stays off rather than assuming on.
     *
     * @param tenantDomain Organization the write belongs to.
     * @return True when the organization enabled this source.
     */
    @Override
    public boolean isEnabled(String tenantDomain) {

        return Boolean.parseBoolean(readProperty(tenantDomain, HIBPConnectorConfig.ENABLE));
    }

    private String resolveApiKey(String tenantDomain) {

        // A tenant key wins over the deployment key. No key is fine: the range endpoint is unauthenticated.
        String configured = normalizeApiKey(readProperty(tenantDomain, HIBPConnectorConfig.API_KEY));
        return configured == null ? deploymentApiKey : configured;
    }

    /** Blank and the {@link HIBPConnectorConfig#NO_API_KEY} placeholder both mean no key. */
    static String normalizeApiKey(String value) {

        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || HIBPConnectorConfig.NO_API_KEY.equalsIgnoreCase(trimmed)) {
            return null;
        }
        return trimmed;
    }

    private String readProperty(String tenantDomain, String name) {

        // A store that cannot be read returns nothing, so the source stays off rather than assuming on.
        try {
            if (HIBPDataHolder.getInstance().getIdentityGovernanceService() == null) {
                return null;
            }
            Property[] properties = HIBPDataHolder.getInstance().getIdentityGovernanceService()
                    .getConfiguration(new String[] { name }, tenantDomain);
            if (properties == null) {
                return null;
            }
            for (Property property : properties) {
                if (property != null && name.equals(property.getName())) {
                    return property.getValue();
                }
            }
        } catch (Exception e) {
            LOG.error("Could not read the Have I Been Pwned configuration for tenant '" + tenantDomain
                    + "'. The source will not be consulted.", e);
        }

        return null;
    }

    /**
     * Hash the candidate, send only the first five characters of the digest, and match the remainder
     * locally. The password and its full digest never leave the deployment.
     *
     * @param credential   Candidate password.
     * @param tenantDomain Organization the write belongs to, used to resolve the failure policy.
     * @return {@link Decision#REFUSE_BREACHED} when the corpus holds the password, otherwise the
     * organization's configured answer for a corpus that could not be reached.
     */
    @Override
    public Decision check(Credential credential, String tenantDomain) {

        String digest = credential.digestHex("SHA-1");
        String prefix = digest.substring(0, 5);
        // Only the prefix is sent. The suffix is compared here.
        String suffix = digest.substring(5);

        Map<String, Long> suffixes;
        try {
            suffixes = client.fetchRange(prefix, resolveApiKey(tenantDomain));
        } catch (Unreachable e) {
            LOG.warn("Have I Been Pwned could not be consulted: " + e.getMessage() + ".");
            return whenUnreachable(tenantDomain);
        }

        return suffixes.containsKey(suffix) ? Decision.REFUSE_BREACHED : Decision.ACCEPT;
    }

    private Decision whenUnreachable(String tenantDomain) {

        String configured = readProperty(tenantDomain, HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE);
        return Boolean.parseBoolean(configured) ? Decision.REFUSE_UNVERIFIED : Decision.ACCEPT;
    }

    /**
     * Release the API key. Called when the bundle stops.
     */
    public void shutdown() {

        deploymentApiKey = null;
    }

}
