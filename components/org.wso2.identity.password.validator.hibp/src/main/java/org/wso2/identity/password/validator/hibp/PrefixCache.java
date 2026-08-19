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

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The one thing in this connector worth caching: the range response for a five-character prefix.
 * <p>
 * That response is stable over hours and is shared by every password in the bucket, so caching it saves a round
 * trip without narrowing anything. The candidate password and its full digest are never cache keys and never
 * cache values - a cache keyed on the digest would be a password store.
 */
class PrefixCache {

    private final int maxEntries;
    private final long ttlMillis;
    private final LinkedHashMap<String, Entry> entries;

    private long hits;
    private long misses;

    PrefixCache(int maxEntries, long ttlMillis) {

        this.maxEntries = Math.max(1, maxEntries);
        this.ttlMillis = ttlMillis;
        this.entries = new LinkedHashMap<String, Entry>(16, 0.75f, true) {

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Entry> eldest) {

                return size() > PrefixCache.this.maxEntries;
            }
        };
    }

    synchronized Map<String, Long> get(String prefix) {

        Entry entry = entries.get(prefix);
        if (entry == null) {
            misses++;
            return null;
        }
        if (System.currentTimeMillis() > entry.expiresAt) {
            entries.remove(prefix);
            misses++;
            return null;
        }
        hits++;
        return entry.suffixes;
    }

    synchronized void put(String prefix, Map<String, Long> suffixes) {

        if (ttlMillis <= 0) {
            return;
        }
        entries.put(prefix, new Entry(new HashMap<>(suffixes), System.currentTimeMillis() + ttlMillis));
    }

    synchronized void clear() {

        entries.clear();
    }

    /**
     * @return the hit ratio as a whole percentage, or -1 when nothing has been looked up yet.
     */
    synchronized int getHitRatioPercent() {

        long total = hits + misses;
        return total == 0 ? -1 : (int) ((hits * 100) / total);
    }

    synchronized int size() {

        return entries.size();
    }

    /**
     * One bucket: the suffixes the range endpoint returned, and when they stop being trusted.
     */
    private static final class Entry {

        private final Map<String, Long> suffixes;
        private final long expiresAt;

        private Entry(Map<String, Long> suffixes, long expiresAt) {

            this.suffixes = suffixes;
            this.expiresAt = expiresAt;
        }
    }
}
