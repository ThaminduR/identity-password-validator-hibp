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
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import java.util.HashMap;
import java.util.Locale;
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

    public static final String PROPERTY_BASE_URL = "base_url";
    public static final String PROPERTY_READ_TIMEOUT_MS = "read_timeout_ms";
    public static final String PROPERTY_CONNECT_TIMEOUT_MS = "connect_timeout_ms";
    public static final String PROPERTY_RETRIES = "retries";

    private static final String DEFAULT_BASE_URL = "https://api.pwnedpasswords.com/range/";
    /** Shorter than the platform's 5000 ms action client default, which is not for a per-write call. */
    private static final int DEFAULT_READ_TIMEOUT_MS = 1500;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_RETRIES = 1;

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
                positive(configuration, PROPERTY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS),
                positive(configuration, PROPERTY_READ_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS),
                Math.max(0, configuration.getInt(PROPERTY_RETRIES, DEFAULT_RETRIES)));

        LOG.info("The Have I Been Pwned connector was configured: endpoint=" + client.getBaseUrl()
                + ", readTimeout=" + client.getReadTimeoutMs() + " ms.");
    }

    /**
     * Read a timeout that must be positive. Zero would wait forever and a negative value is rejected by
     * the connection, so either falls back to the default.
     */
    private static int positive(SourceConfiguration configuration, String name, int defaultValue) {

        int value = configuration.getInt(name, defaultValue);
        if (value > 0) {
            return value;
        }
        LOG.warn("Ignoring " + name + "=" + value + " for the Have I Been Pwned connector; it must be positive. "
                + "Using " + defaultValue + " ms.");
        return defaultValue;
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

        return Boolean.parseBoolean(readProperties(tenantDomain, HIBPConnectorConfig.ENABLE)
                .get(HIBPConnectorConfig.ENABLE));
    }

    private Map<String, String> readProperties(String tenantDomain, String... names) {

        // A store that cannot be read returns nothing. Each caller decides what a missing value means.
        Map<String, String> values = new HashMap<>();
        try {
            IdentityGovernanceService governance = HIBPDataHolder.getInstance().getIdentityGovernanceService();
            if (governance == null) {
                return values;
            }
            Property[] properties = governance.getConfiguration(names, tenantDomain);
            if (properties == null) {
                return values;
            }
            for (Property property : properties) {
                if (property != null && property.getName() != null) {
                    values.put(property.getName(), property.getValue());
                }
            }
        } catch (Exception e) {
            LOG.error("Could not read the Have I Been Pwned configuration for tenant '" + tenantDomain + "'.", e);
        }

        return values;
    }

    /**
     * Hash the candidate, send only the first five characters of the digest, and match the remainder
     * locally. The password and its full digest never leave the deployment.
     *
     * @param credential   Candidate password.
     * @param tenantDomain Organization the write belongs to, used to resolve the failure policy.
     * @return {@link Decision#REFUSE_BREACHED} when the corpus holds the password, otherwise the
     * organization's configured answer for a corpus that could not be reached. A failure inside this
     * connector gets that same answer, rather than escaping to the engine, which would accept the password.
     */
    @Override
    public Decision check(Credential credential, String tenantDomain) {

        try {
            return lookUp(credential, tenantDomain);
        } catch (RuntimeException | LinkageError e) {
            // LinkageError too, because a mismatch with the contract surfaces as one once this code is running.
            LOG.error("Have I Been Pwned failed unexpectedly while checking a password. The organization's "
                    + "failure policy applies.", e);
            return whenUnreachable(tenantDomain);
        }
    }

    private Decision lookUp(Credential credential, String tenantDomain) {

        String digest = credential.digestHex("SHA-1");
        String prefix = digest.substring(0, 5);
        // Only the prefix is sent. The suffix is compared here.
        String suffix = digest.substring(5);

        Map<String, Long> suffixes;
        try {
            suffixes = client.fetchRange(prefix);
        } catch (Unreachable e) {
            LOG.warn("Have I Been Pwned could not be consulted: " + e.getMessage() + ".");
            return whenUnreachable(tenantDomain);
        }

        return isListed(suffixes, suffix) ? Decision.REFUSE_BREACHED : Decision.ACCEPT;
    }

    /**
     * The range keys are uppercase, so the candidate is too, whatever case the digest helper produced.
     */
    static boolean isListed(Map<String, Long> suffixes, String suffix) {

        return suffixes.containsKey(suffix.toUpperCase(Locale.ROOT));
    }

    private Decision whenUnreachable(String tenantDomain) {

        // Read only when needed, so a write normally costs one read. A policy that cannot be read takes the
        // default, refuse, so a store failure during an outage does not let the password through.
        String configured = readProperties(tenantDomain, HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE)
                .get(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE);
        boolean refuse = configured == null || Boolean.parseBoolean(configured.trim());
        return refuse ? Decision.REFUSE_UNVERIFIED : Decision.ACCEPT;
    }

}
