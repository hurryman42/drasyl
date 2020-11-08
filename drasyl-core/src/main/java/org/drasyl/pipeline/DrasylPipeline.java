/*
 * Copyright (c) 2020.
 *
 * This file is part of drasyl.
 *
 *  drasyl is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  drasyl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with drasyl.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.drasyl.pipeline;

import io.reactivex.rxjava3.core.Scheduler;
import org.drasyl.DrasylConfig;
import org.drasyl.event.Event;
import org.drasyl.identity.Identity;
import org.drasyl.peer.Endpoint;
import org.drasyl.peer.PeersManager;
import org.drasyl.peer.connection.PeerChannelGroup;
import org.drasyl.peer.connection.pipeline.DirectConnectionOutboundMessageSinkHandler;
import org.drasyl.peer.connection.pipeline.LoopbackOutboundMessageSinkHandler;
import org.drasyl.peer.connection.pipeline.SuperPeerOutboundMessageSinkHandler;
import org.drasyl.pipeline.codec.ApplicationMessage2ObjectHolderHandler;
import org.drasyl.pipeline.codec.DefaultCodec;
import org.drasyl.pipeline.codec.ObjectHolder2ApplicationMessageHandler;
import org.drasyl.pipeline.codec.TypeValidator;
import org.drasyl.util.DrasylScheduler;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static org.drasyl.peer.connection.pipeline.DirectConnectionOutboundMessageSinkHandler.DIRECT_CONNECTION_OUTBOUND_MESSAGE_SINK_HANDLER;
import static org.drasyl.peer.connection.pipeline.LoopbackOutboundMessageSinkHandler.LOOPBACK_OUTBOUND_MESSAGE_SINK_HANDLER;
import static org.drasyl.peer.connection.pipeline.SuperPeerOutboundMessageSinkHandler.SUPER_PEER_OUTBOUND_MESSAGE_SINK_HANDLER;
import static org.drasyl.pipeline.codec.ApplicationMessage2ObjectHolderHandler.APP_MSG2OBJECT_HOLDER;
import static org.drasyl.pipeline.codec.ObjectHolder2ApplicationMessageHandler.OBJECT_HOLDER2APP_MSG;

/**
 * The default {@link Pipeline} implementation. Used to implement plugins for drasyl.
 */
public class DrasylPipeline extends DefaultPipeline {
    public DrasylPipeline(final Consumer<Event> eventConsumer,
                          final DrasylConfig config,
                          final Identity identity,
                          final PeerChannelGroup channelGroup,
                          final PeersManager peersManager,
                          final AtomicBoolean started,
                          final Set<Endpoint> endpoints) {
        this.handlerNames = new ConcurrentHashMap<>();
        this.inboundValidator = TypeValidator.ofInboundValidator(config);
        this.outboundValidator = TypeValidator.ofOutboundValidator(config);
        this.head = new HeadContext(config, this, DrasylScheduler.getInstanceHeavy(), identity, inboundValidator, outboundValidator);
        this.tail = new TailContext(eventConsumer, config, this, DrasylScheduler.getInstanceHeavy(), identity, inboundValidator, outboundValidator);
        this.scheduler = DrasylScheduler.getInstanceLight();
        this.config = config;
        this.identity = identity;

        initPointer();

        // add default codec
        addFirst(DefaultCodec.DEFAULT_CODEC, DefaultCodec.INSTANCE);
        addFirst(APP_MSG2OBJECT_HOLDER, ApplicationMessage2ObjectHolderHandler.INSTANCE);
        addFirst(OBJECT_HOLDER2APP_MSG, new ObjectHolder2ApplicationMessageHandler(config.getNetworkId()));

        // message sinks for outgoing messages
        addFirst(LOOPBACK_OUTBOUND_MESSAGE_SINK_HANDLER, new LoopbackOutboundMessageSinkHandler(started, peersManager, endpoints));
        addFirst(DIRECT_CONNECTION_OUTBOUND_MESSAGE_SINK_HANDLER, new DirectConnectionOutboundMessageSinkHandler(channelGroup));
        addFirst(SUPER_PEER_OUTBOUND_MESSAGE_SINK_HANDLER, new SuperPeerOutboundMessageSinkHandler(channelGroup, peersManager));
    }

    DrasylPipeline(final Map<String, AbstractHandlerContext> handlerNames,
                   final AbstractEndHandler head,
                   final AbstractEndHandler tail,
                   final Scheduler scheduler,
                   final DrasylConfig config,
                   final Identity identity) {
        this.handlerNames = handlerNames;
        this.head = head;
        this.tail = tail;
        this.scheduler = scheduler;
        this.config = config;
        this.identity = identity;
    }
}