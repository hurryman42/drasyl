/*
 * Copyright (c) 2020-2022 Heiko Bornholdt and Kevin Röbert
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.drasyl.util;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Disabled("This test are not reliable with guava-based implementation")
class ExpiringSetTest {
    @Nested
    class MaximumSize {
        @Test
        void shouldEvictFirstEntriesBasedOnExpirationPolicyWhenSizeIsExceeding() throws InterruptedException {
            final Set<Object> set = new ExpiringSet<>(2, 10);
            set.add("Hallo");
            set.add("Hello");
            set.add("Bonjour");

            assertEquals(2, set.size());
            assertFalse(set.contains("Hallo"));
        }
    }

    @Nested
    class ExpireAfterWrite {
        @Test
        void shouldExpireEntriesBasedOnExpirationPolicy() throws InterruptedException {
            final Set<Object> set = new ExpiringSet<>(-1, 10);

            // accessing the entry should not affect expiration
            set.add("Foo");
            assertTrue(set.contains("Foo"));
            await().untilAsserted(() -> {
                assertFalse(set.contains("Foo"));
            });

            // writing the entry should affect expiration
            for (int i = 0; i < 10; i++) {
                set.add("Baz");
                assertTrue(set.contains("Baz"));
                Thread.sleep(5);
            }
        }
    }
}
