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
import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachSource;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.breach.source.PropertyDescriptor;
import org.wso2.carbon.identity.breach.source.SourceConfiguration;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Checks a candidate against the Have I Been Pwned corpus without sending the password. Five characters of
 * the SHA-1 digest are sent, the service returns every suffix sharing that prefix, and the match is made here.
 * <p>
 * The reference implementation of the SPI, released separately from the core.
 */
public class HIBPBreachSource implements BreachSource {

    private static final Log LOG = LogFactory.getLog(HIBPBreachSource.class);

    public static final String SOURCE_ID = "hibp";

    public static final String PROPERTY_API_KEY = "api_key";
    public static final String PROPERTY_BASE_URL = "base_url";
    public static final String PROPERTY_READ_TIMEOUT_MS = "read_timeout_ms";
    public static final String PROPERTY_CONNECT_TIMEOUT_MS = "connect_timeout_ms";
    public static final String PROPERTY_CACHE_TTL_SECONDS = "cache_ttl_seconds";
    public static final String PROPERTY_CACHE_MAX_ENTRIES = "cache_max_entries";
    public static final String PROPERTY_RETRIES = "retries";
    public static final String PROPERTY_BREAKER_THRESHOLD = "circuit_breaker_failures";
    public static final String PROPERTY_BREAKER_OPEN_SECONDS = "circuit_breaker_open_seconds";

    private static final String DEFAULT_BASE_URL = "https://api.pwnedpasswords.com/range/";
    /**
     * Tighter than the platform's action HTTP client default of 5000 ms, which was chosen for a
     * customer-hosted extension rather than for a call made on every password write.
     */
    private static final int DEFAULT_READ_TIMEOUT_MS = 1500;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 1000;
    private static final int DEFAULT_CACHE_TTL_SECONDS = 3600;
    private static final int DEFAULT_CACHE_MAX_ENTRIES = 5000;
    private static final int DEFAULT_RETRIES = 1;
    private static final int DEFAULT_BREAKER_THRESHOLD = 5;
    private static final int DEFAULT_BREAKER_OPEN_SECONDS = 60;

    private static final String USER_AGENT = "WSO2-Identity-Server-Breach-Detection";

    private volatile String baseUrl = DEFAULT_BASE_URL;
    private volatile String deploymentApiKey;
    private volatile int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
    private volatile int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
    private volatile int retries = DEFAULT_RETRIES;
    private volatile PrefixCache cache = new PrefixCache(DEFAULT_CACHE_MAX_ENTRIES,
            DEFAULT_CACHE_TTL_SECONDS * 1000L);
    private volatile CircuitBreaker breaker = new CircuitBreaker(DEFAULT_BREAKER_THRESHOLD,
            DEFAULT_BREAKER_OPEN_SECONDS * 1000L);


    @Override
    public String getId() {

        return SOURCE_ID;
    }


    @Override
    public List<PropertyDescriptor> getProperties() {

        return Arrays.asList(
                PropertyDescriptor.secret(PROPERTY_API_KEY),
                PropertyDescriptor.optional(PROPERTY_BASE_URL, DEFAULT_BASE_URL),
                PropertyDescriptor.optional(PROPERTY_READ_TIMEOUT_MS, String.valueOf(DEFAULT_READ_TIMEOUT_MS)),
                PropertyDescriptor.optional(PROPERTY_CONNECT_TIMEOUT_MS, String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS)),
                PropertyDescriptor.optional(PROPERTY_CACHE_TTL_SECONDS, String.valueOf(DEFAULT_CACHE_TTL_SECONDS)),
                PropertyDescriptor.optional(PROPERTY_CACHE_MAX_ENTRIES, String.valueOf(DEFAULT_CACHE_MAX_ENTRIES)),
                PropertyDescriptor.optional(PROPERTY_RETRIES, String.valueOf(DEFAULT_RETRIES)),
                PropertyDescriptor.optional(PROPERTY_BREAKER_THRESHOLD, String.valueOf(DEFAULT_BREAKER_THRESHOLD)),
                PropertyDescriptor.optional(PROPERTY_BREAKER_OPEN_SECONDS,
                        String.valueOf(DEFAULT_BREAKER_OPEN_SECONDS)));
    }

    @Override
    public int getPriority() {

        // After any offline source, before slower remote ones.
        return 500;
    }


    @Override
    public void configure(SourceConfiguration configuration) {

        this.baseUrl = configuration.getString(PROPERTY_BASE_URL).orElse(DEFAULT_BASE_URL);
        this.readTimeoutMs = configuration.getInt(PROPERTY_READ_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS);
        this.connectTimeoutMs = configuration.getInt(PROPERTY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS);
        this.retries = Math.max(0, configuration.getInt(PROPERTY_RETRIES, DEFAULT_RETRIES));

        this.deploymentApiKey = readSecret(configuration, PROPERTY_API_KEY);

        this.cache = new PrefixCache(configuration.getInt(PROPERTY_CACHE_MAX_ENTRIES, DEFAULT_CACHE_MAX_ENTRIES),
                configuration.getInt(PROPERTY_CACHE_TTL_SECONDS, DEFAULT_CACHE_TTL_SECONDS) * 1000L);
        this.breaker = new CircuitBreaker(
                configuration.getInt(PROPERTY_BREAKER_THRESHOLD, DEFAULT_BREAKER_THRESHOLD),
                configuration.getInt(PROPERTY_BREAKER_OPEN_SECONDS, DEFAULT_BREAKER_OPEN_SECONDS) * 1000L);

        LOG.info("The Have I Been Pwned connector was configured: endpoint=" + baseUrl + ", readTimeout="
                + readTimeoutMs + " ms, apiKey=" + (deploymentApiKey == null ? "not set" : "set") + ".");
    }

    /**
     * Whether this organization asked for this source. The answer lives in this connector's own governance
     * configuration, which is also what an administrator edits in the Console.
     */
    @Override
    public boolean isEnabled(String tenantDomain) {

        return Boolean.parseBoolean(readProperty(tenantDomain, HIBPConnectorConfig.ENABLE));
    }

    @Override
    public boolean refusesWhenUnavailable(String tenantDomain) {

        return Boolean.parseBoolean(readProperty(tenantDomain, HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE));
    }

    /**
     * The key for this organization, or null. A tenant key wins over the deployment key. A blank key is not
     * a failure: the range endpoint is unauthenticated.
     */
    private String resolveApiKey(String tenantDomain) {

        String configured = normalizeApiKey(readProperty(tenantDomain, HIBPConnectorConfig.API_KEY));
        return configured == null ? deploymentApiKey : configured;
    }

    /**
     * Take a declared secret from the core and wipe the array the SPI handed over: the caller owns it, and
     * leaving it live would keep the key readable in a heap dump for the lifetime of the bundle.
     */
    private static String readSecret(SourceConfiguration configuration, String name) {

        char[] secret = configuration.getSecret(name).orElse(null);
        if (secret == null) {
            return null;
        }
        try {
            return normalizeApiKey(new String(secret));
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    /**
     * Decides whether a configured value is a key. Blank and the {@link HIBPConnectorConfig#NO_API_KEY}
     * placeholder both mean no key.
     */
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

    /**
     * Read one of this connector's own settings for an organization. A store that cannot be read yields
     * nothing rather than an assumption, so the source stays off instead of guessing that it is on.
     */
    private String readProperty(String tenantDomain, String name) {

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



    @Override
    public BreachVerdict evaluate(BreachContext context) {

        String digest = context.getCredential().digestHex("SHA-1");
        String prefix = digest.substring(0, 5);
        // The suffix never leaves this process.
        String suffix = digest.substring(5);

        Map<String, Long> suffixes = cache.get(prefix);
        if (suffixes == null) {
            if (breaker.isOpen()) {
                return BreachVerdict.unavailable(getId(), "calls suspended after repeated failures");
            }
            try {
                suffixes = fetch(prefix, resolveApiKey(context.getTenantDomain()));
            } catch (Unreachable e) {
                return BreachVerdict.unavailable(getId(), e.getMessage());
            }
            cache.put(prefix, suffixes);
        }

        return suffixes.containsKey(suffix) ? BreachVerdict.found(getId()) : BreachVerdict.notFound(getId());
    }

    private Map<String, Long> fetch(String prefix, String key) throws Unreachable {

        Unreachable last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                Map<String, Long> suffixes = request(prefix, key);
                breaker.recordSuccess();
                return suffixes;
            } catch (Unreachable e) {
                last = e;
                if (!e.isRetryable()) {
                    break;
                }
            }
        }
        breaker.recordFailure();
        throw last == null ? new Unreachable("the corpus could not be reached", true) : last;
    }

    private Map<String, Long> request(String prefix, String key) throws Unreachable {

        HttpURLConnection connection = null;
        try {
            URL url = new URL(baseUrl + prefix);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectTimeoutMs);
            connection.setReadTimeout(readTimeoutMs);
            connection.setRequestProperty("User-Agent", USER_AGENT);
            // Padding keeps the response size from revealing how many entries the bucket holds.
            connection.setRequestProperty("Add-Padding", "true");
            if (key != null) {
                connection.setRequestProperty("hibp-api-key", key);
            }

            int status = connection.getResponseCode();
            if (status == 429 || status == 402) {
                throw new Unreachable("rate or quota limit reached", false);
            }
            if (status != 200) {
                throw new Unreachable("the corpus returned HTTP " + status, true);
            }
            return parse(connection.getInputStream());
        } catch (SocketTimeoutException e) {
            throw new Unreachable("no answer within " + readTimeoutMs + " ms", true);
        } catch (IOException e) {
            // The message deliberately carries no URL fragment beyond the endpoint and no credential.
            throw new Unreachable("the corpus could not be reached", true);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private Map<String, Long> parse(InputStream stream) throws Unreachable {

        Map<String, Long> suffixes = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int separator = line.indexOf(':');
                if (separator <= 0) {
                    continue;
                }
                String suffix = line.substring(0, separator).trim().toUpperCase(Locale.ROOT);
                long count;
                try {
                    count = Long.parseLong(line.substring(separator + 1).trim());
                } catch (NumberFormatException e) {
                    continue;
                }
                // Padding rows are returned with a count of zero and are not matches.
                if (count > 0) {
                    suffixes.put(suffix, count);
                }
            }
        } catch (IOException e) {
            throw new Unreachable("the corpus response could not be read", true);
        }
        if (suffixes.isEmpty()) {
            throw new Unreachable("the corpus response contained no usable entries", true);
        }
        return suffixes;
    }

    /**
     * Drop the API key and the cached ranges. Called when the connector bundle stops.
     */
    public void shutdown() {

        deploymentApiKey = null;
        cache.clear();
    }

}
