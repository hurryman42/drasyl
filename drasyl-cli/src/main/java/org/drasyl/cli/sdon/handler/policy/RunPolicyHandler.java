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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import static java.util.Objects.requireNonNull;

public class RunPolicyHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(RunPolicyHandler.class);
    private final RunPolicy policy;
    private Thread processThread;

    public RunPolicyHandler(final RunPolicy policy) {
        this.policy = requireNonNull(policy);
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) throws IOException, InterruptedException {
        //ProcessBuilder processBuilder = new ProcessBuilder("sleep", "10");
        //Process process = processBuilder.start();
        LOG.debug("About to execute: {}", String.join(" ", policy.command));

        processThread = new Thread(() -> {
            try {
                // ProcessBuilder requires splitting the command into the different "words" & input them as a String-Array
                //final File outputFile = new File("logFile1.txt");
                final ProcessBuilder builder = new ProcessBuilder(policy.command.split(" "));
                //builder.inheritIO();
                //builder.redirectErrorStream(true); //--> gives also error stream with the normal output; does not broken output
                //builder.redirectOutput(outputFile); //--> redirects output into a file, but also not live
                //final Process process = builder.start();
                //process.getInputStream().transferTo(System.out);

                final Process process = Runtime.getRuntime().exec(policy.command);

                //LOG.debug("Started process with ID {}", process.pid());
                System.out.println("Started process with ID " + process.pid());

                System.out.flush();

                /*Thread outputThread = new Thread(() -> {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                        String output;
                        while ((output = reader.readLine()) != null) {
                            //LOG.debug("{}", output);
                            System.out.println(output);
                        }
                    }
                    catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
                outputThread.start();*/

                String output;

                // FIXME: loop never enters and therefore never prints (only when process gets killed)
                final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                //final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                //while (reader.ready()) {
                //    LOG.debug("{}", reader.readLine());
                //}
                //System.out.println(reader.read());
                while ((output = reader.readLine()) != null) { // == null bis zur Programmterminierung :(
                    //LOG.debug("{}", output);
                    System.out.println(output);
                    System.out.flush();
                }

                final int exitCode = process.waitFor();
                System.out.println("process exit code: " + exitCode);
                //reader.close();

                //final Thread watcherThread = getWatcherThread(process);
                //watcherThread.start();

                //outputThread.join();
                //watcherThread.join();
            }
            catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        processThread.start();

        System.out.println("------------------------------------------------------------------------------------------------");
    }

    private static Thread getWatcherThread(Process process) {
        final Thread watcherThread = new Thread(() -> {
            while (process.isAlive()) {
                try {
                    System.out.println("Process still running...");
                    Thread.sleep(1000); // FIXME: busy-waiting
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // restore interrupted status
                    break;
                }
            }
            System.out.println("The process has finished!!!");
        });

        watcherThread.setName("watcher");
        return watcherThread;
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        System.out.println("Interrupting processThread.");
        processThread.interrupt();
    }
}
