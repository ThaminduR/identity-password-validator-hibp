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
import org.wso2.carbon.identity.breach.source.BreachSourceException;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.Capability;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.breach.source.Descriptor;
import org.wso2.carbon.identity.breach.source.FailureAction;
import org.wso2.carbon.identity.breach.source.PropertyDescriptor;
import org.wso2.carbon.identity.breach.source.PropertyType;
import org.wso2.carbon.identity.breach.source.SourceConfiguration;
import org.wso2.carbon.identity.breach.source.SourceStatus;
import org.wso2.carbon.identity.breach.source.UnavailableCause;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Checks a candidate against the Have I Been Pwned corpus, without the corpus ever learning the password.
 * <p>
 * The digest is split: five characters go out, thirty-five stay. The service returns every suffix in that
 * bucket - roughly eight hundred of them - and the match happens here. It therefore learns only that someone in
 * this deployment tested a password in a bucket of that size, and never the answer to its own query.
 * <p>
 * This is a connector, not a core component: separately built, separately released, dropped into
 * {@code dropins}, and removable without touching anything in the core. It is also the reference implementation
 * the SPI is documented against.
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
    private volatile char[] apiKey;
    private volatile int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
    private volatile int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
    private volatile int retries = DEFAULT_RETRIES;
    private volatile PrefixCache cache = new PrefixCache(DEFAULT_CACHE_MAX_ENTRIES,
            DEFAULT_CACHE_TTL_SECONDS * 1000L);
    private volatile CircuitBreaker breaker = new CircuitBreaker(DEFAULT_BREAKER_THRESHOLD,
            DEFAULT_BREAKER_OPEN_SECONDS * 1000L);

    private final AtomicLong lastSuccess = new AtomicLong();
    private final AtomicReference<String> lastFailure = new AtomicReference<>();

    @Override
    public String getId() {

        return SOURCE_ID;
    }

    @Override
    public Descriptor getDescriptor() {

        return Descriptor.builder("Have I Been Pwned")
                .description("Checks against a continuously updated public breach corpus.")
                .privacyNotice("Sends only a partial, irreversible fingerprint of the password. "
                        + "The password itself, and the user's identity, never leave this server.")
                .vendor("Have I Been Pwned")
                .documentationUrl("https://haveibeenpwned.com/API/v3#PwnedPasswords")
                .build();
    }

    @Override
    public List<PropertyDescriptor> getProperties() {

        return Arrays.asList(
                PropertyDescriptor.builder(PROPERTY_API_KEY, PropertyType.STRING)
                        .secret(true)
                        .required(false)
                        .displayName("API key")
                        .description("Optional. The range endpoint needs no authentication, and a missing key "
                                + "is never a reason to stop checking.")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_BASE_URL, PropertyType.STRING)
                        .defaultValue(DEFAULT_BASE_URL)
                        .displayName("Range endpoint")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_READ_TIMEOUT_MS, PropertyType.DURATION_MS)
                        .defaultValue(String.valueOf(DEFAULT_READ_TIMEOUT_MS))
                        .displayName("Read timeout")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_CONNECT_TIMEOUT_MS, PropertyType.DURATION_MS)
                        .defaultValue(String.valueOf(DEFAULT_CONNECT_TIMEOUT_MS))
                        .displayName("Connect timeout")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_CACHE_TTL_SECONDS, PropertyType.INTEGER)
                        .defaultValue(String.valueOf(DEFAULT_CACHE_TTL_SECONDS))
                        .displayName("Prefix cache lifetime (seconds)")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_CACHE_MAX_ENTRIES, PropertyType.INTEGER)
                        .defaultValue(String.valueOf(DEFAULT_CACHE_MAX_ENTRIES))
                        .displayName("Prefix cache size")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_RETRIES, PropertyType.INTEGER)
                        .defaultValue(String.valueOf(DEFAULT_RETRIES))
                        .displayName("Retries")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_BREAKER_THRESHOLD, PropertyType.INTEGER)
                        .defaultValue(String.valueOf(DEFAULT_BREAKER_THRESHOLD))
                        .displayName("Failures before the circuit opens")
                        .build(),
                PropertyDescriptor.builder(PROPERTY_BREAKER_OPEN_SECONDS, PropertyType.INTEGER)
                        .defaultValue(String.valueOf(DEFAULT_BREAKER_OPEN_SECONDS))
                        .displayName("Seconds the circuit stays open")
                        .build());
    }

    @Override
    public int getPriority() {

        // After any offline source, before slower remote ones.
        return 500;
    }

    @Override
    public EnumSet<Capability> getCapabilities() {

        return EnumSet.of(Capability.REMOTE, Capability.PASSWORD_ONLY);
    }

    @Override
    public void configure(SourceConfiguration configuration) {

        this.baseUrl = configuration.getString(PROPERTY_BASE_URL).orElse(DEFAULT_BASE_URL);
        this.readTimeoutMs = configuration.getInt(PROPERTY_READ_TIMEOUT_MS, DEFAULT_READ_TIMEOUT_MS);
        this.connectTimeoutMs = configuration.getInt(PROPERTY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS);
        this.retries = Math.max(0, configuration.getInt(PROPERTY_RETRIES, DEFAULT_RETRIES));

        char[] previous = this.apiKey;
        this.apiKey = configuration.getSecret(PROPERTY_API_KEY).orElse(null);
        if (previous != null) {
            Arrays.fill(previous, '\0');
        }

        this.cache = new PrefixCache(configuration.getInt(PROPERTY_CACHE_MAX_ENTRIES, DEFAULT_CACHE_MAX_ENTRIES),
                configuration.getLong(PROPERTY_CACHE_TTL_SECONDS, DEFAULT_CACHE_TTL_SECONDS) * 1000L);
        this.breaker = new CircuitBreaker(
                configuration.getInt(PROPERTY_BREAKER_THRESHOLD, DEFAULT_BREAKER_THRESHOLD),
                configuration.getLong(PROPERTY_BREAKER_OPEN_SECONDS, DEFAULT_BREAKER_OPEN_SECONDS) * 1000L);

        LOG.info("The Have I Been Pwned connector was configured: endpoint=" + baseUrl + ", readTimeout="
                + readTimeoutMs + " ms, apiKey=" + (apiKey == null ? "not set" : "set") + ".");
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
    public FailureAction getFailureAction(String tenantDomain) {

        return Boolean.parseBoolean(readProperty(tenantDomain, HIBPConnectorConfig.DENY_ON_FAILURE))
                ? FailureAction.DENY : FailureAction.ALLOW;
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
    public boolean isConfigured(String tenantDomain) {

        // The range endpoint needs no authentication. A blank key must never be read as a reason to stop
        // enforcing - reporting every password clean while presenting as enabled is the failure this avoids.
        return baseUrl != null && !baseUrl.trim().isEmpty();
    }

    @Override
    public SourceStatus getStatus(String tenantDomain) {

        long success = lastSuccess.get();
        String failure = lastFailure.get();
        SourceStatus.Builder builder = SourceStatus.builder(
                        breaker.isOpen() || (success == 0 && failure != null)
                                ? SourceStatus.State.UNAVAILABLE : SourceStatus.State.READY)
                .lastSuccess(success == 0 ? null : success);
        if (success > 0) {
            builder.fact("LAST SUCCESS", formatTimestamp(success));
        }
        if (failure != null) {
            builder.fact("FAILING WITH", failure);
        }
        int ratio = cache.getHitRatioPercent();
        if (ratio >= 0) {
            builder.fact("CACHE HITS", ratio + "%");
        }
        builder.fact("CACHED PREFIXES", String.valueOf(cache.size()));
        if (breaker.isOpen()) {
            builder.summary("Repeated failures have suspended calls to this source.");
        }
        return builder.build();
    }

    @Override
    public BreachVerdict evaluate(BreachContext context) throws BreachSourceException {

        String digest = context.getCredential().digestHex("SHA-1");
        String prefix = digest.substring(0, 5);
        // The suffix never leaves this process.
        String suffix = digest.substring(5);

        Map<String, Long> suffixes = cache.get(prefix);
        if (suffixes == null) {
            if (breaker.isOpen()) {
                return BreachVerdict.unavailable(getId(), UnavailableCause.CIRCUIT_OPEN,
                        "Calls are suspended after repeated failures.");
            }
            suffixes = fetch(prefix);
            cache.put(prefix, suffixes);
        }

        Long occurrences = suffixes.get(suffix);
        if (occurrences == null) {
            return BreachVerdict.notFound(getId());
        }
        return BreachVerdict.found(getId(), occurrences);
    }

    private Map<String, Long> fetch(String prefix) throws BreachSourceException {

        BreachSourceException last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                Map<String, Long> suffixes = request(prefix);
                breaker.recordSuccess();
                lastSuccess.set(System.currentTimeMillis());
                lastFailure.set(null);
                return suffixes;
            } catch (BreachSourceException e) {
                last = e;
                if (e.getUnavailableCause() == UnavailableCause.QUOTA) {
                    // Retrying an exhausted quota only exhausts it further.
                    break;
                }
            }
        }
        breaker.recordFailure();
        lastFailure.set(last == null ? "unknown failure" : last.getMessage());
        throw last == null
                ? new BreachSourceException(UnavailableCause.TRANSPORT, "The corpus could not be reached.")
                : last;
    }

    private Map<String, Long> request(String prefix) throws BreachSourceException {

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
            char[] key = apiKey;
            if (key != null && key.length > 0) {
                connection.setRequestProperty("hibp-api-key", new String(key));
            }

            int status = connection.getResponseCode();
            if (status == 429 || status == 402) {
                throw new BreachSourceException(UnavailableCause.QUOTA,
                        "The corpus rejected the request for rate or quota reasons.");
            }
            if (status != 200) {
                throw new BreachSourceException(UnavailableCause.TRANSPORT,
                        "The corpus returned HTTP " + status + ".");
            }
            return parse(connection.getInputStream());
        } catch (SocketTimeoutException e) {
            throw new BreachSourceException(UnavailableCause.TIMEOUT,
                    "The corpus did not answer within " + readTimeoutMs + " ms.");
        } catch (IOException e) {
            // The message deliberately carries no URL fragment beyond the endpoint and no credential.
            throw new BreachSourceException(UnavailableCause.TRANSPORT, "The corpus could not be reached.");
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private Map<String, Long> parse(InputStream stream) throws BreachSourceException {

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
            throw new BreachSourceException(UnavailableCause.PARSE, "The corpus response could not be read.");
        }
        if (suffixes.isEmpty()) {
            throw new BreachSourceException(UnavailableCause.PARSE,
                    "The corpus response contained no usable entries.");
        }
        return suffixes;
    }

    /**
     * Release the API key. Called when the connector bundle stops.
     */
    public void shutdown() {

        char[] key = apiKey;
        apiKey = null;
        if (key != null) {
            Arrays.fill(key, '\0');
        }
        cache.clear();
    }

    private static String formatTimestamp(long epochMillis) {

        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date(epochMillis));
    }
}
