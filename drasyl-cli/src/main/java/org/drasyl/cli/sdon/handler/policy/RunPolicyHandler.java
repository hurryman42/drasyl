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
package org.drasyl.cli.sdon.handler.policy;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.drasyl.cli.sdon.config.RunPolicy;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.IOException;

import static java.util.Objects.requireNonNull;

public class RunPolicyHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(RunPolicyHandler.class);
    private final RunPolicy policy;

    public RunPolicyHandler(final RunPolicy policy) {
        this.policy = requireNonNull(policy);
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) throws IOException {
        try {
            //ProcessBuilder processBuilder = new ProcessBuilder("sleep", "10");
            //Process process = processBuilder.start();

            LOG.trace("Execute: {}", String.join(" ", policy.command));
            final Process process = Runtime.getRuntime().exec(policy.command);
            System.out.println(process.pid());
            final Thread watcherThread = getWatcherThread(process);
            watcherThread.start();
            final int exitCode = process.waitFor();
            watcherThread.join();
        }
        catch (final InterruptedException e) {
            Thread.currentThread().interrupt(); // restore interrupted status
        }

        System.out.println("------------------------------------------------------------------------------------------------");
    }

    private static Thread getWatcherThread(Process process) {
        final Thread watcherThread = new Thread(() -> {
            while (true) {
                if (!process.isAlive()) {
                    System.out.println("The process has finished!!!");
                    break;
                }
                try {
                    System.out.println("Process still running...");
                    Thread.sleep(1000); // busy-waiting with sleep
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // restore interrupted status
                    break;
                }
            }
        });
        watcherThread.setName("watcher");
        return watcherThread;
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        System.out.println("-----");
    }
}
