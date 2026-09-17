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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * An outage must cost the deployment one timeout, not one per registration.
 */
public class CircuitBreakerTest {

    @Test
    public void itOpensOnlyAfterTheConfiguredNumberOfFailures() {

        CircuitBreaker breaker = new CircuitBreaker(3, 60000);
        breaker.recordFailure();
        breaker.recordFailure();
        assertFalse(breaker.isOpen());
        breaker.recordFailure();
        assertTrue(breaker.isOpen());
    }

    @Test
    public void oneSuccessClosesIt() {

        CircuitBreaker breaker = new CircuitBreaker(2, 60000);
        breaker.recordFailure();
        breaker.recordFailure();
        assertTrue(breaker.isOpen());
        breaker.recordSuccess();
        assertFalse(breaker.isOpen());
    }

    @Test
    public void afterTheCooldownOneCallIsLetThroughToSeeIfTheServiceCameBack() throws InterruptedException {

        CircuitBreaker breaker = new CircuitBreaker(2, 60);
        breaker.recordFailure();
        breaker.recordFailure();
        assertTrue(breaker.isOpen());
        Thread.sleep(100);
        assertFalse(breaker.isOpen());
    }

    /**
     * The probe after the cooldown must admit exactly one caller. Admitting all of them sends the whole
     * backlog at a service that has just been failing, which is the load the breaker exists to withhold.
     */
    @Test
    public void theProbeAfterTheCooldownAdmitsExactlyOneCaller() throws InterruptedException {

        CircuitBreaker breaker = new CircuitBreaker(2, 50);
        breaker.recordFailure();
        breaker.recordFailure();
        assertTrue(breaker.isOpen());
        Thread.sleep(120);

        int threads = 50;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger admitted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    if (!breaker.isOpen()) {
                        admitted.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS), "the probe threads did not finish");

        assertEquals(admitted.get(), 1, "only one caller may probe the recovering service");
    }
}
