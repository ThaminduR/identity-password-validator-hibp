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
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.breach.detection.model.Credential;
import org.wso2.carbon.identity.breach.detection.model.Decision;
import org.wso2.carbon.identity.breach.detection.spi.SourceConfiguration;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.identity.password.validator.hibp.internal.HIBPDataHolder;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
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
import static org.testng.Assert.assertThrows;
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
    private final Map<String, String> governanceValues = new HashMap<>();
    private final List<String> governanceTenants = new ArrayList<>();
    private final AtomicInteger governanceReads = new AtomicInteger();
    private volatile boolean governanceFails;
    private final AtomicInteger requests = new AtomicInteger();
    private volatile int status = 200;
    private volatile String body;

    @BeforeMethod
    public void startStubEndpoint() throws IOException {

        requestedPaths.clear();
        paddingHeaders.clear();
        governanceValues.clear();
        governanceTenants.clear();
        governanceReads.set(0);
        governanceFails = false;
        HIBPDataHolder.getInstance().setIdentityGovernanceService(null);
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
        HIBPDataHolder.getInstance().setIdentityGovernanceService(null);
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

    /** Nothing is held between calls, so each check is answered from a fresh range lookup. */
    @Test
    public void everyCheckConsultsTheCorpusRatherThanAnythingHeldInMemory() throws Exception {

        HIBPBreachSource source = source();
        source.check(candidate(BREACHED), TENANT);
        source.check(candidate(BREACHED), TENANT);
        assertEquals(requests.get(), 2);
    }

    /**
     * A corpus that cannot be reached is never reported as breached. What happens instead is the failure
     * policy this organization configured, which refuses as unverified when no policy can be read.
     */
    @Test
    public void anExhaustedQuotaAppliesTheFailurePolicyAndIsNotReportedAsBreached() {

        status = 429;
        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void aServerErrorAppliesTheFailurePolicyAndIsNotReportedAsBreached() {

        status = 503;
        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_UNVERIFIED);
    }

    /** A policy store that cannot be read during an outage takes the default, refuse, rather than allowing. */
    @Test
    public void anUnreadablePolicyDuringAnOutageRefusesAsUnverified() {

        governanceFails = true;
        governance(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE, "false");
        status = 503;

        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_UNVERIFIED);
    }

    /**
     * A failure inside the connector gets the organization's failure policy. Escaping to the engine would
     * accept the password, even where the organization chose to refuse.
     */
    @Test
    public void anUnexpectedFailureAppliesTheFailurePolicyRatherThanEscaping() {

        Credential cleared = candidate(BREACHED);
        cleared.clear();

        // No policy stored, so the default, refuse.
        assertEquals(source().check(cleared, TENANT), Decision.REFUSE_UNVERIFIED);

        governance(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE, "false");
        assertEquals(source().check(cleared, TENANT), Decision.ACCEPT);
        assertEquals(requests.get(), 0, "The failure came before any call, so none was made.");
    }

    /** The match does not depend on the case the digest helper produces. */
    @Test
    public void aLowercaseSuffixStillMatchesTheUppercaseRange() {

        Map<String, Long> range = new HashMap<>();
        String suffix = sha1(BREACHED).substring(5);
        range.put(suffix.toUpperCase(Locale.ROOT), 1L);

        assertTrue(HIBPBreachSource.isListed(range, suffix.toLowerCase(Locale.ROOT)));
        assertTrue(HIBPBreachSource.isListed(range, suffix.toUpperCase(Locale.ROOT)));
        assertFalse(HIBPBreachSource.isListed(range, sha1("CleanPassword@9").substring(5)));
    }

    /** Every attempt is bounded, so a failing endpoint costs a timeout per write and never hangs. */
    @Test
    public void aFailingEndpointIsRetriedAtMostTheConfiguredNumberOfTimes() throws Exception {

        status = 503;
        HIBPBreachSource source = source(config().set(HIBPBreachSource.PROPERTY_RETRIES, 1));

        assertEquals(source.check(candidate(BREACHED), TENANT), Decision.REFUSE_UNVERIFIED);

        assertEquals(requests.get(), 2, "one attempt plus one retry, and no more");
    }

    /**
     * A 200 that holds no range rows, such as a proxy or captive portal page, is not an answer. Reading it as
     * not listed would accept a breached password even where the organization set the policy to refuse.
     */
    @Test
    public void aSuccessfulResponseWithNoRangeRowsIsUnreachableRatherThanNotListed() {

        body = "<html><body>Please sign in to the network: 12</body></html>\r\nnot-a-row:5\r\n";
        HIBPRangeClient client = new HIBPRangeClient(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/range/", 2000, 2000, 1);

        assertThrows(Unreachable.class, () -> client.fetchRange(sha1(BREACHED).substring(0, 5)));
        assertEquals(requests.get(), 1, "A body that is not a range answer will not become one on retry.");
    }

    /** A timeout of zero would wait forever and a negative one throws, so both fall back to the default. */
    @Test
    public void nonPositiveTimeoutsFallBackToTheDefaultsAndStillCheck() {

        HIBPBreachSource negative = source(config()
                .set(HIBPBreachSource.PROPERTY_READ_TIMEOUT_MS, -1)
                .set(HIBPBreachSource.PROPERTY_CONNECT_TIMEOUT_MS, -1));
        assertEquals(negative.check(candidate(BREACHED), TENANT), Decision.REFUSE_BREACHED);

        HIBPBreachSource zero = source(config()
                .set(HIBPBreachSource.PROPERTY_READ_TIMEOUT_MS, 0)
                .set(HIBPBreachSource.PROPERTY_CONNECT_TIMEOUT_MS, 0));
        assertEquals(zero.check(candidate(BREACHED), TENANT), Decision.REFUSE_BREACHED);
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

    /** The organization chose to refuse when the corpus cannot answer, so an outage refuses as unverified. */
    @Test
    public void anOrganizationThatChoseToRefuseIsRefusedAsUnverifiedDuringAnOutage() {

        governance(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE, "true");
        status = 503;

        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void anOrganizationThatChoseToAllowIsAcceptedDuringAnOutage() {

        governance(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE, "false");
        status = 503;

        assertEquals(source().check(candidate(BREACHED), TENANT), Decision.ACCEPT);
    }

    /** An outage is never reported as breached, even where the organization chose to refuse. */
    @Test
    public void aRefusalDuringAnOutageIsNeverReportedAsBreached() {

        governance(HIBPConnectorConfig.REFUSE_WHEN_UNREACHABLE, "true");
        body = "<html>captive portal</html>";

        assertEquals(source().check(candidate("CleanPassword@9"), TENANT), Decision.REFUSE_UNVERIFIED);
    }

    @Test
    public void enablementIsTheOrganizationsOwnSetting() {

        HIBPBreachSource source = source();
        assertFalse(source.isEnabled(TENANT), "Nothing is stored, so the source is off.");

        governance(HIBPConnectorConfig.ENABLE, "true");
        assertTrue(source.isEnabled(TENANT));
        assertEquals(governanceTenants.get(governanceTenants.size() - 1), TENANT);
    }

    /** A store that cannot be read keeps the source off rather than assuming on. */
    @Test
    public void aGovernanceStoreThatCannotBeReadKeepsTheSourceOff() {

        governanceFails = true;
        governance(HIBPConnectorConfig.ENABLE, "true");

        assertFalse(source().isEnabled(TENANT));
    }

    /** A write reads one governance setting, and the failure policy only when it is needed. */
    @Test
    public void aReachableCheckReadsNoGovernanceSettingBeyondEnablement() {

        governance(HIBPConnectorConfig.ENABLE, "true");
        HIBPBreachSource source = source();

        assertTrue(source.isEnabled(TENANT));
        assertEquals(source.check(candidate(BREACHED), TENANT), Decision.REFUSE_BREACHED);
        assertEquals(governanceReads.get(), 1);

        status = 503;
        source.check(candidate(BREACHED), TENANT);
        assertEquals(governanceReads.get(), 2, "An outage adds one read, for the failure policy.");
        assertEquals(governanceTenants.get(governanceTenants.size() - 1), TENANT);
    }

    private void governance(String name, String value) {

        governanceValues.put(name, value);
        if (HIBPDataHolder.getInstance().getIdentityGovernanceService() != null) {
            return;
        }
        IdentityGovernanceService service = (IdentityGovernanceService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[] { IdentityGovernanceService.class },
                (proxy, method, args) -> {
                    if (!"getConfiguration".equals(method.getName()) || args == null || args.length != 2
                            || !(args[0] instanceof String[])) {
                        throw new UnsupportedOperationException(method.getName());
                    }
                    governanceReads.incrementAndGet();
                    governanceTenants.add((String) args[1]);
                    if (governanceFails) {
                        throw new IdentityGovernanceException("store unavailable");
                    }
                    List<Property> found = new ArrayList<>();
                    for (String requested : (String[]) args[0]) {
                        if (governanceValues.containsKey(requested)) {
                            Property property = new Property();
                            property.setName(requested);
                            property.setValue(governanceValues.get(requested));
                            found.add(property);
                        }
                    }
                    return found.toArray(new Property[0]);
                });
        HIBPDataHolder.getInstance().setIdentityGovernanceService(service);
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
