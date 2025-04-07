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
import org.drasyl.cli.sdon.config.ControlledPolicy;
import org.drasyl.cli.sdon.handler.SdonDeviceHandler;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import static java.lang.System.out;
import static java.util.Objects.requireNonNull;

public class ControlledPolicyHandler extends ChannelInboundHandlerAdapter {
    //private static final Logger LOG = LoggerFactory.getLogger(SubControllerPolicyHandler.class);
    private final ControlledPolicy policy;

    public ControlledPolicyHandler(final ControlledPolicy policy) {
        this.policy = requireNonNull(policy);
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) {
        final SdonDeviceHandler deviceHandler = ctx.pipeline().get(SdonDeviceHandler.class);
        deviceHandler.fallbackController = deviceHandler.controller;
        final IdentityPublicKey controllerPublicKey = (IdentityPublicKey) policy.controller(); //IdentityPublicKey.of(policy.controller().toString());
        deviceHandler.controller = controllerPublicKey;

        out.println("------------------------------------------------------------------------------------------------");
        out.println("My new CONTROLLER is: " + controllerPublicKey);
        out.println("------------------------------------------------------------------------------------------------");
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        final SdonDeviceHandler deviceHandler = ctx.pipeline().get(SdonDeviceHandler.class);
        deviceHandler.controller = deviceHandler.fallbackController;
        deviceHandler.fallbackController = null;
    }
}
