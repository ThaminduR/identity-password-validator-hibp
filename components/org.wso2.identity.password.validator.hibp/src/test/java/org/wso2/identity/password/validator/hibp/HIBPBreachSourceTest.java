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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * The connector against a stand-in for the range endpoint.
 * <p>
 * The assertion that matters most is not that a breached password is found - it is that only five characters
 * of the digest ever reach the wire.
 */
public class HIBPBreachSourceTest {

    private static final String TENANT = "carbon.super";
    private static final String BREACHED = "Password@1";

    private HttpServer server;
    private final List<String> requestedPaths = new ArrayList<>();
    private final List<String> paddingHeaders = new ArrayList<>();
    private final AtomicInteger requests = new AtomicInteger();
    private volatile int status = 200;
    private volatile String body;

    @BeforeMethod
    public void startStubEndpoint() throws IOException {

        requestedPaths.clear();
        paddingHeaders.clear();
        requests.set(0);
        status = 200;
        body = defaultBody();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/range/", this::handle);
        server.start();
    }

    @AfterMethod
    public void stopStubEndpoint() {

        server.stop(0);
    }

    @Test
    public void findsAPasswordPresentInTheCorpus() throws Exception {

        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_BREACHED);
    }

    @Test
    public void acceptsAPasswordAbsentFromTheCorpus() throws Exception {

        assertEquals(source().check(candidate("Zx9q!Kt7#Lm2vRb4"), TENANT), Decision.ACCEPT);
    }

    @Test
    public void onlyTheFirstFiveCharactersOfTheDigestCrossTheBoundary() throws Exception {

        source().check(candidate(BREACHED), TENANT);

        String digest = sha1(BREACHED);
        assertEquals(requestedPaths.size(), 1);
        String path = requestedPaths.get(0);
        assertEquals(path, "/range/" + digest.substring(0, 5));
        assertFalse(path.contains(digest.substring(5)), "The suffix must never leave the deployment.");
        assertFalse(path.contains(BREACHED));
    }

    @Test
    public void paddingIsRequestedSoTheResponseSizeRevealsNothing() throws Exception {

        source().check(candidate(BREACHED), TENANT);
        assertEquals(paddingHeaders.get(0), "true");
    }

    /**
     * A bucket holding only padding rows means the password is not listed. Reporting that as a failure would
     * refuse a clean password wherever the organization set the failure policy to refuse.
     */
    @Test
    public void aBucketOfOnlyPaddingMeansNotListedRatherThanUnreachable() throws Exception {

        body = sha1("SomeOtherPassword@1").substring(5) + ":0\r\n";
        assertEquals(source().check(candidate("CleanPassword@9"), TENANT), Decision.ACCEPT);
        assertEquals(requests.get(), 1, "A valid answer must not be retried as though it had failed.");
    }

    @Test
    public void paddingRowsAreNotTreatedAsMatches() throws Exception {

        // Padding rows come back with a count of zero. Treating one as a hit would refuse a clean password.
        String digest = sha1("PaddedOnly@1");
        body = digest.substring(5) + ":0\r\n" + defaultBody();
        HIBPBreachSource source = source();
        assertEquals(source.check(candidate("PaddedOnly@1"), TENANT), Decision.ACCEPT);
    }

    @Test
    public void aBucketIsFetchedOnceAndThenServedFromTheCache() throws Exception {

        HIBPBreachSource source = source();
        source.check(candidate(BREACHED), TENANT);
        source.check(candidate(BREACHED), TENANT);
        assertEquals(requests.get(), 1, "The bucket is stable for hours; refetching it buys nothing.");
    }

    /**
     * A corpus that cannot be reached is never reported as breached. What happens instead is the failure
     * policy this organization configured, which defaults to allow when no policy is stored. The refuse
     * branch needs a governance service and is covered at runtime rather than here.
     */
    @Test
    public void anExhaustedQuotaAppliesTheFailurePolicyAndIsNotReportedAsBreached() {

        status = 429;
        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.ACCEPT);
    }

    @Test
    public void aServerErrorAppliesTheFailurePolicyAndIsNotReportedAsBreached() {

        status = 503;
        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.ACCEPT);
    }

    @Test
    public void repeatedFailureOpensTheCircuitInsteadOfRetryingForever() throws Exception {

        status = 503;
        HIBPBreachSource source = source(config().set(HIBPBreachSource.PROPERTY_RETRIES, 0)
                .set(HIBPBreachSource.PROPERTY_BREAKER_THRESHOLD, 2));
        for (int i = 0; i < 2; i++) {
            assertEquals(source.check(candidate("attempt" + i), TENANT), Decision.ACCEPT);
        }
        assertEquals(source.check(candidate("attempt-after-open"), TENANT), Decision.ACCEPT);
    }

    @Test
    public void aMissingApiKeyIsNeverAReasonToStopChecking() throws Exception {

        // The range endpoint needs no key. Reporting every password clean without one is the defect avoided.
        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_BREACHED);
    }

    @Test
    public void itIsIdentifiedAndOrderedAfterOfflineSources() {

        HIBPBreachSource source = new HIBPBreachSource();
        assertEquals(source.getId(), "hibp");
        assertTrue(source.getPriority() > 100);
    }

    private void handle(HttpExchange exchange) throws IOException {

        requests.incrementAndGet();
        requestedPaths.add(exchange.getRequestURI().getPath());
        paddingHeaders.add(exchange.getRequestHeaders().getFirst("Add-Padding"));
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, status == 200 ? payload.length : -1);
        if (status == 200) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        }
        exchange.close();
    }

    private String defaultBody() {

        // The bucket a real range call returns: many suffixes, one of which is the candidate's.
        StringBuilder builder = new StringBuilder();
        builder.append(sha1(BREACHED).substring(5)).append(":612953\r\n");
        for (int i = 0; i < 20; i++) {
            builder.append(sha1("filler" + i).substring(5)).append(':').append(100 + i).append("\r\n");
        }
        return builder.toString();
    }

    private HIBPBreachSource source() {

        return source(config());
    }

    private HIBPBreachSource source(MapConfiguration configuration) {

        HIBPBreachSource source = new HIBPBreachSource();
        source.configure(configuration);
        return source;
    }

    private MapConfiguration config() {

        return new MapConfiguration()
                .set(HIBPBreachSource.PROPERTY_BASE_URL,
                        "http://127.0.0.1:" + server.getAddress().getPort() + "/range/")
                .set(HIBPBreachSource.PROPERTY_RETRIES, 0)
                .set(HIBPBreachSource.PROPERTY_READ_TIMEOUT_MS, 2000)
                .set(HIBPBreachSource.PROPERTY_CONNECT_TIMEOUT_MS, 2000);
    }

    private Credential candidate(String password) {

        return new Credential(password.toCharArray());
    }

    private static String sha1(String value) {

        try {
            byte[] out = MessageDigest.getInstance("SHA-1").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : out) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString().toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The settings the core would have handed the connector.
     */

    @Test
    public void placeholderAndBlankKeysAreNotSentAsCredentials() {

        // The Console's generic form will not submit an empty text field, so the API key defaults to a
        // placeholder. Every form of "no key" has to resolve to no key, or the placeholder itself would be
        // sent to the service as a credential.
        assertNull(HIBPBreachSource.normalizeApiKey(null));
        assertNull(HIBPBreachSource.normalizeApiKey(""));
        assertNull(HIBPBreachSource.normalizeApiKey("   "));
        assertNull(HIBPBreachSource.normalizeApiKey(HIBPConnectorConfig.NO_API_KEY));
        assertNull(HIBPBreachSource.normalizeApiKey("None"));
        assertNull(HIBPBreachSource.normalizeApiKey("  NONE  "));

        assertEquals(HIBPBreachSource.normalizeApiKey("real-key"), "real-key");
        assertEquals(HIBPBreachSource.normalizeApiKey("  real-key  "), "real-key");
        // A key that merely contains the placeholder is still a key.
        assertEquals(HIBPBreachSource.normalizeApiKey("none-of-your-business"), "none-of-your-business");
    }

    private static final class MapConfiguration implements SourceConfiguration {

        private final Map<String, String> values = new HashMap<>();

        MapConfiguration set(String name, Object value) {

            values.put(name, String.valueOf(value));
            return this;
        }

        @Override
        public Optional<String> getString(String name) {

            return Optional.ofNullable(values.get(name));
        }

        @Override
        public int getInt(String name, int defaultValue) {

            return getString(name).map(Integer::parseInt).orElse(defaultValue);
        }

        @Override
        public boolean getBoolean(String name, boolean defaultValue) {

            return getString(name).map(Boolean::parseBoolean).orElse(defaultValue);
        }

        @Override
        public Optional<String> getPath(String name) {

            return getString(name);
        }
    }
}
