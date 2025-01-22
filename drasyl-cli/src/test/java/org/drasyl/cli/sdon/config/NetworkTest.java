/*
 * Copyright (c) 2020-2025 Heiko Bornholdt and Kevin Röbert
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
package org.drasyl.cli.sdon.config;

import org.drasyl.util.SetMultimap;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.luaj.vm2.LuaFunction;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.lib.jse.JsePlatform;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class NetworkTest {
    @Nested
    class SetCallback {
        @Test
        void shouldSetCallback(@Mock Map<LuaString, NetworkNode> nodes,
                               @Mock Set<NetworkLink> links,
                               @Mock SetMultimap<LuaString, NetworkLink> nodeLinks) {
            final LuaFunction callback = (LuaFunction) JsePlatform.standardGlobals().load("return function(net, devices) return NIL end").call();

            final Network network = new Network(nodes, links, nodeLinks, 0, null);
            network.setCallback(callback);

            assertNotNull(network.callback);
        }
    }

    @Nested
    class CallCallback {
        @Test
        void shouldCallCallback(@Mock Map<LuaString, NetworkNode> nodes,
                                @Mock Set<NetworkLink> links,
                                @Mock SetMultimap<LuaString, NetworkLink> nodeLinks,
                                @Mock LuaFunction callback,
                                @Mock final Devices devices) {
            final Network network = new Network(nodes, links, nodeLinks, 0, callback);

            network.callCallback(devices);

            verify(callback).call(eq(network), any());
        }
    }
}
