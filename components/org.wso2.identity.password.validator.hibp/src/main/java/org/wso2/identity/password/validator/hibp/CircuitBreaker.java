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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Stops calling a service that has repeatedly failed, so an outage does not make every registration pay the
 * full timeout.
 */
class CircuitBreaker {

    private final int failureThreshold;
    private final long openMillis;

    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicLong openedAt = new AtomicLong();

    CircuitBreaker(int failureThreshold, long openMillis) {

        this.failureThreshold = Math.max(1, failureThreshold);
        this.openMillis = openMillis;
    }

    /**
     * @return whether calls are currently being suppressed.
     */
    boolean isOpen() {

        long opened = openedAt.get();
        if (opened == 0) {
            return false;
        }
        if (System.currentTimeMillis() - opened >= openMillis) {
            // Let one call through to find out whether the service came back.
            openedAt.set(0);
            consecutiveFailures.set(failureThreshold - 1);
            return false;
        }
        return true;
    }

    void recordSuccess() {

        consecutiveFailures.set(0);
        openedAt.set(0);
    }

    void recordFailure() {

        if (consecutiveFailures.incrementAndGet() >= failureThreshold) {
            openedAt.compareAndSet(0, System.currentTimeMillis());
        }
    }
}
