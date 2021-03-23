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
import org.drasyl.loopback.handler.LoopbackMessageHandler;
import org.drasyl.monitoring.Monitoring;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.serialization.MessageSerializer;
import org.drasyl.pipeline.serialization.Serialization;
import org.drasyl.remote.handler.ArmHandler;
import org.drasyl.remote.handler.ChunkingHandler;
import org.drasyl.remote.handler.HopCountGuard;
import org.drasyl.remote.handler.IntermediateEnvelopeToByteBufCodec;
import org.drasyl.remote.handler.InternetDiscoveryHandler;
import org.drasyl.remote.handler.InvalidProofOfWorkFilter;
import org.drasyl.remote.handler.OtherNetworkFilter;
import org.drasyl.remote.handler.StaticRoutesHandler;
import org.drasyl.remote.handler.UdpServer;
import org.drasyl.remote.handler.portmapper.PortMapper;
import org.drasyl.util.scheduler.DrasylScheduler;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.drasyl.util.scheduler.DrasylSchedulerUtil.getInstanceHeavy;
import static org.drasyl.util.scheduler.DrasylSchedulerUtil.getInstanceLight;

/**
 * The default {@link Pipeline} implementation. Used to implement plugins for drasyl.
 */
public class DrasylPipeline extends AbstractPipeline {
    public static final String LOOPBACK_MESSAGE_HANDLER = "LOOPBACK_OUTBOUND_MESSAGE_SINK_HANDLER";
    public static final String INTRA_VM_DISCOVERY = "INTRA_VM_DISCOVERY";
    public static final String MESSAGE_SERIALIZER = "MESSAGE_SERIALIZER";
    public static final String STATIC_ROUTES_HANDLER = "STATIC_ROUTES_HANDLER";
    public static final String LOCAL_HOST_DISCOVERY = "LOCAL_HOST_DISCOVERY";
    public static final String INTERNET_DISCOVERY_HANDLER = "INTERNET_DISCOVERY_HANDLER";
    public static final String HOP_COUNT_GUARD = "HOP_COUNT_GUARD";
    public static final String MONITORING_HANDLER = "MONITORING_HANDLER";
    public static final String ARM_HANDLER = "ARM_HANDLER";
    public static final String INVALID_PROOF_OF_WORK_FILTER = "INVALID_PROOF_OF_WORK_FILTER";
    public static final String OTHER_NETWORK_FILTER = "OTHER_NETWORK_FILTER";
    public static final String CHUNKING_HANDLER = "CHUNKING_HANDLER";
    public static final String INTERMEDIATE_ENVELOPE_TO_BYTE_BUF_CODEC = "INTERMEDIATE_ENVELOPE_TO_BYTE_BUF_CODEC";
    public static final String PORT_MAPPER = "PORT_MAPPER";
    public static final String UDP_SERVER = "UDP_SERVER";

    @SuppressWarnings({ "java:S107" })
    DrasylPipeline(final Consumer<Event> eventConsumer,
                   final DrasylConfig config,
                   final Identity identity,
                   final PeersManager peersManager,
                   final Supplier<UdpServer> udpServerProvider) {
        super(
                new ConcurrentHashMap<>(),
                getInstanceLight(),
                getInstanceHeavy(),
                config,
                identity,
                peersManager,
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsInbound()),
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsOutbound())
        );
        this.head = new HeadContext(config, this, dependentScheduler, independentScheduler, identity, peersManager, inboundSerialization, outboundSerialization);
        this.tail = new TailContext(eventConsumer, config, this, dependentScheduler, independentScheduler, identity, peersManager, inboundSerialization, outboundSerialization);

        initPointer();

        // convert outbound messages addresses to us to inbound messages
        addFirst(LOOPBACK_MESSAGE_HANDLER, new LoopbackMessageHandler());

        // discover nodes running within the same jvm.
        if (config.isIntraVmDiscoveryEnabled()) {
            addFirst(INTRA_VM_DISCOVERY, IntraVmDiscovery.INSTANCE);
        }

        if (config.isRemoteEnabled()) {
            // convert Object <-> IntermediateEnvelope<Application>
            addFirst(MESSAGE_SERIALIZER, MessageSerializer.INSTANCE);

            // route outbound messages to pre-configures ip addresses
            if (!config.getRemoteStaticRoutes().isEmpty()) {
                addFirst(STATIC_ROUTES_HANDLER, StaticRoutesHandler.INSTANCE);
            }

            if (config.isRemoteLocalHostDiscoveryEnabled()) {
                // discover nodes running on the same local computer
                addFirst(LOCAL_HOST_DISCOVERY, new LocalHostDiscovery());
            }

            // register at super peers/discover nodes in other networks
            addFirst(INTERNET_DISCOVERY_HANDLER, new InternetDiscoveryHandler(config));

            // outbound message guards
            addFirst(HOP_COUNT_GUARD, HopCountGuard.INSTANCE);

            if (config.isMonitoringEnabled()) {
                addFirst(MONITORING_HANDLER, new Monitoring());
            }

            // arm (sign/encrypt) outbound and disarm (verify/decrypt) inbound messages
            if (config.isRemoteMessageArmEnabled()) {
                addFirst(ARM_HANDLER, ArmHandler.INSTANCE);
            }

            // filter out inbound messages with invalid proof of work or other network id
            addFirst(INVALID_PROOF_OF_WORK_FILTER, InvalidProofOfWorkFilter.INSTANCE);
            addFirst(OTHER_NETWORK_FILTER, OtherNetworkFilter.INSTANCE);

            // split messages too big for udp
            addFirst(CHUNKING_HANDLER, new ChunkingHandler());

            // convert IntermediateEnvelope <-> ByteBuf
            addFirst(INTERMEDIATE_ENVELOPE_TO_BYTE_BUF_CODEC, IntermediateEnvelopeToByteBufCodec.INSTANCE);

            // udp server
            if (config.isRemoteExposeEnabled()) {
                addFirst(PORT_MAPPER, new PortMapper());
            }
            addFirst(UDP_SERVER, udpServerProvider.get());
        }
    }

    DrasylPipeline(final Map<String, AbstractHandlerContext> handlerNames,
                   final AbstractEndHandler head,
                   final AbstractEndHandler tail,
                   final DrasylScheduler dependentScheduler,
                   final DrasylConfig config,
                   final Identity identity) {
        super(
                handlerNames,
                dependentScheduler,
                getInstanceHeavy(),
                config,
                identity,
                new PeersManager(event -> {
                }, identity),
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsInbound()),
                new Serialization(config.getSerializationSerializers(), config.getSerializationsBindingsOutbound())
        );
        this.head = head;
        this.tail = tail;
    }

    public DrasylPipeline(final Consumer<Event> eventConsumer,
                          final DrasylConfig config,
                          final Identity identity,
                          final PeersManager peersManager,
                          final EventLoopGroup bossGroup) {
        this(eventConsumer, config, identity, peersManager, () -> new UdpServer(bossGroup));
    }
}
