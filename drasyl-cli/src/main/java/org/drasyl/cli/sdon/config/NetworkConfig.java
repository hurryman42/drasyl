/*
 * Copyright (c) 2020-2024 Heiko Bornholdt and Kevin Röbert
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

import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import org.luaj.vm2.Globals;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.lib.jse.JsePlatform;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

public class NetworkConfig {
    private static final Logger LOG = LoggerFactory.getLogger(NetworkConfig.class);
    private final Network network;

    public NetworkConfig(final Network network) {
        this.network = requireNonNull(network);
    }

    public static NetworkConfig parseFile(final File file) throws IOException {
        LOG.debug("Loading network config from `{}`:", file);
        if (!file.exists()) {
            throw new FileNotFoundException(file.getAbsolutePath());
        }
        final Worm<Network> network = Worm.of();
        final LuaValue chunk = globals(network).loadfile(file.toString());
        chunk.call();

        if (network.isEmpty()) {
            throw new IOException("No network has been registered. Have you called register_network(net)?");
        }

        return new NetworkConfig(network.get());
    }

    private static Globals globals(final Worm<Network> network) {
        final Globals globals = JsePlatform.standardGlobals();
        globals.load(new ControllerLib(network));
        return globals;
    }

    public Network network() {
        return network;
    }
}
