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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.netty.channel.ChannelPipeline;
import io.netty.util.internal.StringUtil;
import org.drasyl.cli.sdon.handler.policy.RunPolicyHandler;

import java.io.File;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

public class RunPolicy extends AbstractPolicy {
    public static final String HANDLER_NAME = StringUtil.simpleClassName(RunPolicy.class);
    public final String command;

    @JsonCreator
    public RunPolicy(@JsonProperty("command") final String command) {
        this.command = requireNonNull(command);
    }

    @Override
    public void addPolicy(final ChannelPipeline pipeline) {
        pipeline.addLast(HANDLER_NAME, new RunPolicyHandler(this));
    }

    @Override
    public void removePolicy(final ChannelPipeline pipeline) {
        pipeline.remove(HANDLER_NAME);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final RunPolicy that = (RunPolicy) o;
        return Objects.equals(command, that.command);
    }

    @Override
    public int hashCode() {
        return Objects.hash(command);
    }

    @Override
    public String toString() {
        return "RunPolicy{" +
                "command" + command +
                "}";
    }
}
