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

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * The cache holds buckets, never credentials.
 */
public class PrefixCacheTest {

    @Test
    public void aCachedBucketIsReturnedUntilItExpires() throws InterruptedException {

        PrefixCache cache = new PrefixCache(10, 80);
        cache.put("ABCDE", bucket());
        assertNotNull(cache.get("ABCDE"));
        Thread.sleep(120);
        assertNull(cache.get("ABCDE"), "An expired bucket must be fetched again, not trusted.");
    }

    @Test
    public void theCacheIsBoundedBySize() {

        PrefixCache cache = new PrefixCache(2, 60000);
        cache.put("AAAAA", bucket());
        cache.put("BBBBB", bucket());
        cache.put("CCCCC", bucket());
        assertEquals(cache.size(), 2);
    }

    @Test
    public void aZeroLifetimeDisablesCachingRatherThanCachingForever() {

        PrefixCache cache = new PrefixCache(10, 0);
        cache.put("ABCDE", bucket());
        assertNull(cache.get("ABCDE"));
    }

    @Test
    public void theHitRatioIsReportableForTheAdministratorSurface() {

        PrefixCache cache = new PrefixCache(10, 60000);
        assertEquals(cache.getHitRatioPercent(), -1);
        cache.put("ABCDE", bucket());
        cache.get("ABCDE");
        cache.get("ZZZZZ");
        assertTrue(cache.getHitRatioPercent() > 0 && cache.getHitRatioPercent() < 100);
    }

    private static Map<String, Long> bucket() {

        Map<String, Long> suffixes = new HashMap<>();
        suffixes.put("0123456789012345678901234567890123456", 42L);
        return suffixes;
    }
}
