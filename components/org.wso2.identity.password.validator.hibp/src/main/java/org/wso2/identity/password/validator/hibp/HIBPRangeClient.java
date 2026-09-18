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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * HTTP client for the Have I Been Pwned range API.
 * <p>
 * Holds everything about talking to the service: the endpoint, the timeouts, the retry count and the
 * response format. It is given a digest prefix and never sees a password or a full digest. Immutable, so
 * reconfiguring the source builds a new client rather than mutating one that a call may be using.
 */
class HIBPRangeClient {

    private static final String USER_AGENT = "WSO2-Identity-Server-Breach-Detection";

    private final String baseUrl;
    private final int connectTimeoutMs;
    private final int readTimeoutMs;
    private final int retries;

    HIBPRangeClient(String baseUrl, int connectTimeoutMs, int readTimeoutMs, int retries) {

        // The prefix is appended directly, so an endpoint without a trailing separator would 404.
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        this.retries = Math.max(0, retries);
    }

    /**
     * Get the endpoint this client calls, normalized to end with a separator.
     *
     * @return The base URL.
     */
    String getBaseUrl() {

        return baseUrl;
    }

    /**
     * Get the read timeout applied to each attempt.
     *
     * @return The read timeout in milliseconds.
     */
    int getReadTimeoutMs() {

        return readTimeoutMs;
    }

    /**
     * Fetch every suffix the corpus holds for one digest prefix, retrying only a failure that could succeed
     * on another attempt.
     *
     * @param prefix First five characters of the candidate's SHA-1 digest.
     * @param apiKey Key to present, or null. The range endpoint needs none.
     * @return The suffixes carrying a non-zero count, keyed uppercase.
     * @throws Unreachable If every attempt failed.
     */
    Map<String, Long> fetchRange(String prefix, String apiKey) throws Unreachable {

        Unreachable last = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                return request(prefix, apiKey);
            } catch (Unreachable e) {
                last = e;
                if (!e.isRetryable()) {
                    break;
                }
            }
        }
        throw last == null ? new Unreachable("the corpus could not be reached", true) : last;
    }

    private Map<String, Long> request(String prefix, String apiKey) throws Unreachable {

        HttpURLConnection connection = null;
        try {
            URL url = new URL(baseUrl + prefix);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectTimeoutMs);
            connection.setReadTimeout(readTimeoutMs);
            connection.setRequestProperty("User-Agent", USER_AGENT);
            // Padding stops the response size from revealing how many entries the bucket holds.
            connection.setRequestProperty("Add-Padding", "true");
            if (apiKey != null) {
                connection.setRequestProperty("hibp-api-key", apiKey);
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
            throw new Unreachable("no answer within the configured timeouts, connect " + connectTimeoutMs
                    + " ms and read " + readTimeoutMs + " ms", true);
        } catch (IOException e) {
            // The message carries no URL beyond the endpoint and no credential.
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
                // A padding row is returned with a count of zero and is not a match.
                if (count > 0) {
                    suffixes.put(suffix, count);
                }
            }
        } catch (IOException e) {
            throw new Unreachable("the corpus response could not be read", true);
        }
        // An empty map is a valid answer, not a failure. With padding requested the endpoint returns rows
        // with a count of zero, and a bucket holding only those means the password is simply not listed.
        return suffixes;
    }
}
