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
 * Caches the range response for a five-character prefix, which is stable for hours. The password and its
 * full digest are never a key or a value: a cache keyed on the full digest would be a store of passwords.
 */
class PrefixCache {

    private final int maxEntries;
    private final long ttlMillis;
    private final LinkedHashMap<String, Entry> entries;

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
            return null;
        }
        if (System.currentTimeMillis() > entry.expiresAt) {
            entries.remove(prefix);
            return null;
        }
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

    synchronized int size() {

        return entries.size();
    }

    /** The suffixes the range endpoint returned, and when they expire. */
    private static final class Entry {

        private final Map<String, Long> suffixes;
        private final long expiresAt;

        private Entry(Map<String, Long> suffixes, long expiresAt) {

            this.suffixes = suffixes;
            this.expiresAt = expiresAt;
        }
    }
}
