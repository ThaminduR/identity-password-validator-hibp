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
import org.wso2.carbon.identity.breach.source.BreachContext;
import org.wso2.carbon.identity.breach.source.BreachSourceException;
import org.wso2.carbon.identity.breach.source.BreachVerdict;
import org.wso2.carbon.identity.breach.source.Credential;
import org.wso2.carbon.identity.breach.source.Outcome;
import org.wso2.carbon.identity.breach.source.SourceConfiguration;
import org.wso2.carbon.identity.breach.source.UnavailableCause;

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
import static org.testng.Assert.fail;

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

        assertEquals(source().evaluate(context(BREACHED)).getOutcome(), Outcome.FOUND);
    }


    @Test
    public void acceptsAPasswordAbsentFromTheCorpus() throws Exception {

        assertEquals(source().evaluate(context("Zx9q!Kt7#Lm2vRb4")).getOutcome(), Outcome.NOT_FOUND);
    }

    @Test
    public void onlyTheFirstFiveCharactersOfTheDigestCrossTheBoundary() throws Exception {

        source().evaluate(context(BREACHED));

        String digest = sha1(BREACHED);
        assertEquals(requestedPaths.size(), 1);
        String path = requestedPaths.get(0);
        assertEquals(path, "/range/" + digest.substring(0, 5));
        assertFalse(path.contains(digest.substring(5)), "The suffix must never leave the deployment.");
        assertFalse(path.contains(BREACHED));
    }

    @Test
    public void paddingIsRequestedSoTheResponseSizeRevealsNothing() throws Exception {

        source().evaluate(context(BREACHED));
        assertEquals(paddingHeaders.get(0), "true");
    }

    @Test
    public void paddingRowsAreNotTreatedAsMatches() throws Exception {

        // Padding rows come back with a count of zero. Treating one as a hit would refuse a clean password.
        String digest = sha1("PaddedOnly@1");
        body = digest.substring(5) + ":0\r\n" + defaultBody();
        HIBPBreachSource source = source();
        assertEquals(source.evaluate(context("PaddedOnly@1")).getOutcome(), Outcome.NOT_FOUND);
    }

    @Test
    public void aBucketIsFetchedOnceAndThenServedFromTheCache() throws Exception {

        HIBPBreachSource source = source();
        source.evaluate(context(BREACHED));
        source.evaluate(context(BREACHED));
        assertEquals(requests.get(), 1, "The bucket is stable for hours; refetching it buys nothing.");
    }

    @Test
    public void aRateLimitIsDistinguishableFromATransportFailure() {

        status = 429;
        try {
            source().evaluate(context(BREACHED));
            fail("An exhausted quota must not be reported as a clean password.");
        } catch (BreachSourceException e) {
            assertEquals(e.getUnavailableCause(), UnavailableCause.QUOTA);
        }
    }

    @Test
    public void aServerErrorIsATransportFailureAndNeverANotFound() {

        status = 503;
        try {
            source().evaluate(context(BREACHED));
            fail("A failing corpus must not be reported as a clean password.");
        } catch (BreachSourceException e) {
            assertEquals(e.getUnavailableCause(), UnavailableCause.TRANSPORT);
        }
    }

    @Test
    public void repeatedFailureOpensTheCircuitInsteadOfRetryingForever() throws Exception {

        status = 503;
        HIBPBreachSource source = source(config().set(HIBPBreachSource.PROPERTY_RETRIES, 0)
                .set(HIBPBreachSource.PROPERTY_BREAKER_THRESHOLD, 2));
        for (int i = 0; i < 2; i++) {
            try {
                source.evaluate(context("attempt" + i));
            } catch (BreachSourceException expected) {
                assertEquals(expected.getUnavailableCause(), UnavailableCause.TRANSPORT);
            }
        }
        BreachVerdict verdict = source.evaluate(context("attempt-after-open"));
        assertEquals(verdict.getOutcome(), Outcome.UNAVAILABLE);
        assertEquals(verdict.getCause().orElse(null), UnavailableCause.CIRCUIT_OPEN);
    }

    @Test
    public void aMissingApiKeyIsNeverAReasonToStopChecking() throws Exception {

        // The range endpoint needs no key. Reporting every password clean without one is the defect avoided.
        assertEquals(source().evaluate(context(BREACHED)).getOutcome(), Outcome.FOUND);
    }

    @Test
    public void itIsIdentifiedAndOrderedAfterOfflineSources() {

        HIBPBreachSource source = new HIBPBreachSource();
        assertEquals(source.getId(), "hibp");
        assertTrue(source.getPriority() > 100);
    }

    @Test
    public void theApiKeyIsDeclaredSecretSoItCannotBeReturnedByAnyApi() {

        assertTrue(new HIBPBreachSource().getProperties().stream()
                .filter(p -> HIBPBreachSource.PROPERTY_API_KEY.equals(p.getName()))
                .allMatch(p -> p.isSecret() && !p.isRequired()));
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

    private BreachContext context(String password) {

        return BreachContext.builder()
                .credential(new Credential(password.toCharArray()))
                .tenantDomain(TENANT)
                .build();
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
        public long getLong(String name, long defaultValue) {

            return getString(name).map(Long::parseLong).orElse(defaultValue);
        }

        @Override
        public boolean getBoolean(String name, boolean defaultValue) {

            return getString(name).map(Boolean::parseBoolean).orElse(defaultValue);
        }

        @Override
        public Optional<char[]> getSecret(String name) {

            return getString(name).map(String::toCharArray);
        }

        @Override
        public Optional<String> getPath(String name) {

            return getString(name);
        }
    }
}
