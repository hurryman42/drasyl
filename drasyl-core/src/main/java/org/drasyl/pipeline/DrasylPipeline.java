/*
 * Copyright (c) 2020-2021.
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

import io.netty.channel.EventLoopGroup;
import org.drasyl.DrasylConfig;
import org.drasyl.event.Event;
import org.drasyl.identity.Identity;
import org.drasyl.intravm.IntraVmDiscovery;
import org.drasyl.localhost.LocalHostDiscovery;
import org.drasyl.loopback.handler.InboundMessageGuard;
import org.drasyl.loopback.handler.LoopbackMessageHandler;
import org.drasyl.monitoring.Monitoring;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.serialization.MessageSerializer;
import org.drasyl.remote.handler.*;
import org.drasyl.remote.handler.portmapper.PortMapper;
import org.drasyl.util.scheduler.DrasylScheduler;
import org.drasyl.util.scheduler.DrasylSchedulerUtil;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static org.drasyl.intravm.IntraVmDiscovery.INTRA_VM_DISCOVERY;
import static org.drasyl.localhost.LocalHostDiscovery.LOCAL_HOST_DISCOVERY;
import static org.drasyl.loopback.handler.InboundMessageGuard.INBOUND_MESSAGE_GUARD;
import static org.drasyl.loopback.handler.LoopbackMessageHandler.LOOPBACK_MESSAGE_HANDLER;
import static org.drasyl.monitoring.Monitoring.MONITORING_HANDLER;
import static org.drasyl.pipeline.AddressedEnvelopeHandler.ADDRESSED_ENVELOPE_HANDLER;
import static org.drasyl.pipeline.serialization.MessageSerializer.MESSAGE_SERIALIZER;
import static org.drasyl.remote.handler.ByteBuf2MessageHandler.BYTE_BUF_2_MESSAGE_HANDLER;
import static org.drasyl.remote.handler.ChunkingHandler.CHUNKING_HANDLER;
import static org.drasyl.remote.handler.HopCountGuard.HOP_COUNT_GUARD;
import static org.drasyl.remote.handler.InvalidProofOfWorkFilter.INVALID_PROOF_OF_WORK_FILTER;
import static org.drasyl.remote.handler.Message2ByteBufHandler.MESSAGE_2_BYTE_BUF_HANDLER;
import static org.drasyl.remote.handler.OtherNetworkFilter.OTHER_NETWORK_FILTER;
import static org.drasyl.remote.handler.SignatureHandler.SIGNATURE_HANDLER;
import static org.drasyl.remote.handler.StaticRoutesHandler.STATIC_ROUTES_HANDLER;
import static org.drasyl.remote.handler.UdpDiscoveryHandler.UDP_DISCOVERY_HANDLER;
import static org.drasyl.remote.handler.UdpServer.UDP_SERVER;
import static org.drasyl.remote.handler.portmapper.PortMapper.PORT_MAPPER;

/**
 * The default {@link Pipeline} implementation. Used to implement plugins for drasyl.
 */
public class DrasylPipeline extends DefaultPipeline {
    @SuppressWarnings({ "java:S107" })
    public DrasylPipeline(final Consumer<Event> eventConsumer,
                          final DrasylConfig config,
                          final Identity identity,
                          final PeersManager peersManager,
                          final EventLoopGroup bossGroup) {
        this.handlerNames = new ConcurrentHashMap<>();
        this.inboundSerialization = new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsInbound());
        this.outboundSerialization = new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsOutbound());
        this.dependentScheduler = DrasylSchedulerUtil.getInstanceLight();
        this.independentScheduler = DrasylSchedulerUtil.getInstanceHeavy();
        this.head = new HeadContext(config, this, dependentScheduler, independentScheduler, identity, peersManager, inboundSerialization, outboundSerialization);
        this.tail = new TailContext(eventConsumer, config, this, dependentScheduler, independentScheduler, identity, peersManager, inboundSerialization, outboundSerialization);
        this.config = config;
        this.identity = identity;
        this.peersManager = peersManager;

        initPointer();

        // convert msg <-> AddressedEnvelopeHandler(msg)
        addFirst(ADDRESSED_ENVELOPE_HANDLER, AddressedEnvelopeHandler.INSTANCE);

        addFirst(INBOUND_MESSAGE_GUARD, new InboundMessageGuard());

        // local message delivery
        addFirst(LOOPBACK_MESSAGE_HANDLER, new LoopbackMessageHandler());

        if (config.isLocalHostDiscoveryEnabled()) {
            addFirst(LOCAL_HOST_DISCOVERY, new LocalHostDiscovery());
        }

        // we trust peers within the same jvm. therefore we do not use signatures
        if (config.isIntraVmDiscoveryEnabled()) {
            addFirst(INTRA_VM_DISCOVERY, IntraVmDiscovery.INSTANCE);
        }

        if (config.isRemoteEnabled()) {
            addFirst(MESSAGE_SERIALIZER, MessageSerializer.INSTANCE);

            if (!config.getRemoteStaticRoutes().isEmpty()) {
                addFirst(STATIC_ROUTES_HANDLER, new StaticRoutesHandler());
            }

            addFirst(UDP_DISCOVERY_HANDLER, new UdpDiscoveryHandler(config));

            // outbound message guards
            addFirst(HOP_COUNT_GUARD, HopCountGuard.INSTANCE);

            if (config.isMonitoringEnabled()) {
                addFirst(MONITORING_HANDLER, new Monitoring());
            }

            addFirst(SIGNATURE_HANDLER, SignatureHandler.INSTANCE);

            // inbound message guards
            addFirst(INVALID_PROOF_OF_WORK_FILTER, InvalidProofOfWorkFilter.INSTANCE);
            addFirst(OTHER_NETWORK_FILTER, OtherNetworkFilter.INSTANCE);

            addFirst(CHUNKING_HANDLER, new ChunkingHandler());

            // (de)serialize messages
            addFirst(MESSAGE_2_BYTE_BUF_HANDLER, Message2ByteBufHandler.INSTANCE);
            addFirst(BYTE_BUF_2_MESSAGE_HANDLER, ByteBuf2MessageHandler.INSTANCE);

            // udp server
            if (config.isRemoteExposeEnabled()) {
                addFirst(PORT_MAPPER, new PortMapper());
            }
            addFirst(UDP_SERVER, new UdpServer(bossGroup));
        }
    }

    DrasylPipeline(final Map<String, AbstractHandlerContext> handlerNames,
                   final AbstractEndHandler head,
                   final AbstractEndHandler tail,
                   final DrasylScheduler scheduler,
                   final DrasylConfig config,
                   final Identity identity) {
        this.handlerNames = handlerNames;
        this.head = head;
        this.tail = tail;
        this.dependentScheduler = scheduler;
        this.config = config;
        this.identity = identity;
    }
}
