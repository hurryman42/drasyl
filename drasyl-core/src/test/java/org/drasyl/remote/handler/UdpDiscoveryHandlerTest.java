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
package org.drasyl.remote.handler;

import com.google.protobuf.MessageLite;
import io.reactivex.rxjava3.observers.TestObserver;
import org.drasyl.DrasylConfig;
import org.drasyl.event.Event;
import org.drasyl.event.NodeDownEvent;
import org.drasyl.event.NodeEvent;
import org.drasyl.event.NodeUnrecoverableErrorEvent;
import org.drasyl.event.NodeUpEvent;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.identity.Identity;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.EmbeddedPipeline;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Serialization;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.address.InetSocketAddressWrapper;
import org.drasyl.pipeline.serialization.SerializedApplicationMessage;
import org.drasyl.remote.handler.UdpDiscoveryHandler.OpenPing;
import org.drasyl.remote.handler.UdpDiscoveryHandler.Peer;
import org.drasyl.remote.protocol.AddressedIntermediateEnvelope;
import org.drasyl.remote.protocol.IntermediateEnvelope;
import org.drasyl.remote.protocol.MessageId;
import org.drasyl.remote.protocol.Protocol.Acknowledgement;
import org.drasyl.remote.protocol.Protocol.Application;
import org.drasyl.remote.protocol.Protocol.Discovery;
import org.drasyl.remote.protocol.Protocol.Unite;
import org.drasyl.util.Pair;
import org.drasyl.util.TypeReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import static java.time.Duration.ofSeconds;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.drasyl.remote.protocol.Protocol.MessageType.ACKNOWLEDGEMENT;
import static org.drasyl.remote.protocol.Protocol.MessageType.APPLICATION;
import static org.drasyl.remote.protocol.Protocol.MessageType.UNITE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Answers.RETURNS_DEEP_STUBS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UdpDiscoveryHandlerTest {
    @Mock(answer = RETURNS_DEEP_STUBS)
    private DrasylConfig config;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Identity identity;
    @Mock
    private Serialization inboundSerialization;
    @Mock
    private Serialization outboundSerialization;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Map<MessageId, OpenPing> openPingsCache;
    @Mock
    private PeersManager peersManager;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Set<CompressedPublicKey> rendezvousPeers;
    @Mock
    private Map<Pair<CompressedPublicKey, CompressedPublicKey>, Boolean> uniteAttemptsCache;
    @Mock(answer = RETURNS_DEEP_STUBS)
    private Map<CompressedPublicKey, Peer> peers;

    @Test
    void shouldPassthroughAllOtherEvents(@Mock final NodeEvent event) {
        final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, rendezvousPeers);
        final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
        final TestObserver<Event> inboundEvents = pipeline.inboundEvents().test();

        pipeline.processInbound(event).join();

        inboundEvents.awaitCount(1)
                .assertValueCount(1)
                .assertValue(m -> m instanceof NodeEvent);
        pipeline.close();
    }

    @Nested
    class DoHeartbeat {
        @Test
        void shouldStartHeartbeatingOnNodeUpEvent(@Mock final NodeUpEvent event) {
            when(config.getRemotePingInterval()).thenReturn(ofSeconds(5));

            final UdpDiscoveryHandler handler = spy(new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, rendezvousPeers));
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(event).join();

            verify(handler).startHeartbeat(any());
            pipeline.close();
        }

        @Test
        void shouldStopHeartbeatingOnNodeUnrecoverableErrorEvent(@Mock(answer = RETURNS_DEEP_STUBS) final CompressedPublicKey publicKey,
                                                                 @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                                 @Mock final NodeUnrecoverableErrorEvent event) {
            final HashMap<CompressedPublicKey, Peer> peers = new HashMap<>(Map.of(publicKey, peer));
            final UdpDiscoveryHandler handler = spy(new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, rendezvousPeers));
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(event).join();

            verify(handler).stopHeartbeat();
            verify(openPingsCache).clear();
            verify(uniteAttemptsCache).clear();
            verify(rendezvousPeers).remove(publicKey);
            assertTrue(peers.isEmpty());
            pipeline.close();
        }

        @Test
        void shouldStopHeartbeatingOnNodeDownEvent(@Mock(answer = RETURNS_DEEP_STUBS) final CompressedPublicKey publicKey,
                                                   @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                   @Mock final NodeDownEvent event) {
            final HashMap<CompressedPublicKey, Peer> peers = new HashMap<>(Map.of(publicKey, peer));
            final UdpDiscoveryHandler handler = spy(new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, rendezvousPeers));
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(event).join();

            verify(handler).stopHeartbeat();
            verify(openPingsCache).clear();
            verify(uniteAttemptsCache).clear();
            verify(rendezvousPeers).remove(publicKey);
            assertTrue(peers.isEmpty());
            pipeline.close();
        }

        @Test
        void shouldReplyWithAcknowledgmentMessageToDiscoveryMessage(@Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                                    @Mock(answer = RETURNS_DEEP_STUBS) final InetSocketAddressWrapper address,
                                                                    @Mock final InetSocketAddressWrapper senderAddress,
                                                                    @Mock final InetSocketAddressWrapper recipientAddress) {
            final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
            final IntermediateEnvelope<Discovery> discoveryMessage = IntermediateEnvelope.discovery(0, sender, ProofOfWork.of(6518542), recipient, System.currentTimeMillis());
            final AddressedIntermediateEnvelope<Discovery> addressedDiscoveryMessage = new AddressedIntermediateEnvelope<>(senderAddress, recipientAddress, discoveryMessage);

            when(identity.getPublicKey()).thenReturn(recipient);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(sender, peer)), rendezvousPeers);
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
            final TestObserver<Object> outboundMessages = pipeline.outboundMessages().test();

            pipeline.processInbound(address, addressedDiscoveryMessage);

            outboundMessages.awaitCount(1)
                    .assertValueCount(1)
                    .assertValue(m -> m instanceof AddressedIntermediateEnvelope && ((AddressedIntermediateEnvelope<?>) m).getContent().getPrivateHeader().getType() == ACKNOWLEDGEMENT);
            verify(peersManager, never()).addPath(any(), any());
            pipeline.close();
        }

        @Test
        void shouldUpdatePeerInformationOnAcknowledgementMessageFromNormalPeer(@Mock(answer = RETURNS_DEEP_STUBS) final InetSocketAddressWrapper address,
                                                                               @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                                               @Mock final InetSocketAddressWrapper senderAddress,
                                                                               @Mock final InetSocketAddressWrapper recipientAddress) throws IOException {
            final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
            final IntermediateEnvelope<Acknowledgement> acknowledgementMessage = IntermediateEnvelope.acknowledgement(0, sender, ProofOfWork.of(6518542), recipient, MessageId.randomMessageId());
            final AddressedIntermediateEnvelope<Acknowledgement> addressedAcknowledgementMessage = new AddressedIntermediateEnvelope<>(senderAddress, recipientAddress, acknowledgementMessage);

            when(identity.getPublicKey()).thenReturn(recipient);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(new HashMap<>(Map.of(MessageId.of(acknowledgementMessage.getBody().getCorrespondingId().toByteArray()), new OpenPing(address))), uniteAttemptsCache, new HashMap<>(Map.of(sender, peer)), rendezvousPeers);
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(address, addressedAcknowledgementMessage).join();

            verify(peersManager).addPath(any(), any());
            pipeline.close();
        }

        @Test
        void shouldUpdatePeerInformationOnAcknowledgementMessageFromSuperPeer(@Mock(answer = RETURNS_DEEP_STUBS) final InetSocketAddressWrapper address,
                                                                              @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                                              @Mock final InetSocketAddressWrapper senderAddress,
                                                                              @Mock final InetSocketAddressWrapper recipientAddress) throws IOException {
            final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
            final IntermediateEnvelope<Acknowledgement> acknowledgementMessage = IntermediateEnvelope.acknowledgement(0, sender, ProofOfWork.of(6518542), recipient, MessageId.randomMessageId());
            final AddressedIntermediateEnvelope<Acknowledgement> addressedAcknowledgementMessage = new AddressedIntermediateEnvelope<>(senderAddress, recipientAddress, acknowledgementMessage);

            when(peer.getAddress()).thenReturn(new InetSocketAddressWrapper(22527));
            when(identity.getPublicKey()).thenReturn(recipient);
            when(config.getRemoteSuperPeerEndpoint().getPublicKey()).thenReturn(sender);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(new HashMap<>(Map.of(MessageId.of(acknowledgementMessage.getBody().getCorrespondingId().toByteArray()), new OpenPing(address))), uniteAttemptsCache, new HashMap<>(Map.of(sender, peer)), rendezvousPeers);
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(address, addressedAcknowledgementMessage).join();

            verify(peersManager).addPathAndSetSuperPeer(any(), any());
            pipeline.close();
        }

        @Test
        void shouldNotRemoveLivingSuperPeer(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx,
                                            @Mock final CompressedPublicKey publicKey,
                                            @Mock final InetSocketAddressWrapper address,
                                            @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer) {
            when(peer.getAddress()).thenReturn(address);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(publicKey, peer)), new HashSet<>());
            handler.doHeartbeat(ctx);

            verifyNoInteractions(peersManager);
        }

        @Test
        void shouldRemoveDeadSuperPeer(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx,
                                       @Mock final CompressedPublicKey publicKey,
                                       @Mock final InetSocketAddressWrapper address,
                                       @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer) {
            when(peer.getAddress()).thenReturn(address);
            when(ctx.config().getRemoteSuperPeerEndpoint().getPublicKey()).thenReturn(publicKey);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(publicKey, peer)), new HashSet<>());
            handler.doHeartbeat(ctx);

            verify(ctx.peersManager()).unsetSuperPeerAndRemovePath(any());
        }

        @Test
        void shouldRemoveDeadChildrenOrPeers(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx,
                                             @Mock final CompressedPublicKey publicKey,
                                             @Mock final InetSocketAddressWrapper address,
                                             @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer) {
            when(peer.getAddress()).thenReturn(address);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(publicKey, peer)), new HashSet<>());
            handler.doHeartbeat(ctx);

            verify(ctx.peersManager()).removeChildrenAndPath(eq(publicKey), any());
        }

        @Test
        void shouldPingSuperPeer(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx) {
            final CompressedPublicKey myPublicKey = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey publicKey = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");

            when(ctx.config().isRemoteSuperPeerEnabled()).thenReturn(true);
            when(ctx.config().getRemoteSuperPeerEndpoint().getHost()).thenReturn("127.0.0.1");
            when(ctx.identity().getPublicKey()).thenReturn(myPublicKey);
            when(ctx.config().getRemoteSuperPeerEndpoint().getPublicKey()).thenReturn(publicKey);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, new HashSet<>());
            handler.doHeartbeat(ctx);

            verify(ctx).write(any(), any(AddressedIntermediateEnvelope.class), any());
        }

        @Test
        void shouldPingPeersWithRecentCommunication(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx,
                                                    @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer) {
            final CompressedPublicKey myPublicKey = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey publicKey = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");

            when(peer.hasControlTraffic(any())).thenReturn(true);
            when(peer.hasApplicationTraffic(any())).thenReturn(true);
            when(ctx.identity().getPublicKey()).thenReturn(myPublicKey);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(publicKey, peer)), new HashSet<>(Set.of(publicKey)));
            handler.doHeartbeat(ctx);

            verify(ctx).write(any(), any(AddressedIntermediateEnvelope.class), any());
        }

        @Test
        void shouldNotPingPeersWithoutRecentCommunication(@Mock(answer = RETURNS_DEEP_STUBS) final HandlerContext ctx,
                                                          @Mock(answer = RETURNS_DEEP_STUBS) final Peer peer) {
            final CompressedPublicKey publicKey = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");

            when(peer.hasControlTraffic(any())).thenReturn(true);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(publicKey, peer)), new HashSet<>(Set.of(publicKey)));
            handler.doHeartbeat(ctx);

            verify(ctx, never()).write(any(), any(), any());
            verify(ctx.peersManager()).removeChildrenAndPath(eq(publicKey), any());
        }
    }

    @Nested
    class Uniting {
        @Test
        void shouldHandleUniteMessageFromSuperPeer(@Mock(answer = RETURNS_DEEP_STUBS) final Peer peer,
                                                   @Mock(answer = RETURNS_DEEP_STUBS) final InetSocketAddressWrapper address,
                                                   @Mock final InetSocketAddressWrapper senderAddress,
                                                   @Mock final InetSocketAddressWrapper recipientAddress) throws IOException {
            final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
            final IntermediateEnvelope<Unite> uniteMessage = IntermediateEnvelope.unite(0, sender, ProofOfWork.of(6518542), recipient, CompressedPublicKey.of("03409386a22294ee55393eb0f83483c54f847f700df687668cc8aa3caa19a9df7a"), new InetSocketAddress(22527));
            final AddressedIntermediateEnvelope<Unite> addressedUniteMessage = new AddressedIntermediateEnvelope<>(senderAddress, recipientAddress, uniteMessage);

            when(config.getRemoteSuperPeerEndpoint().getPublicKey()).thenReturn(sender);
            when(identity.getPublicKey()).thenReturn(recipient);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(CompressedPublicKey.of(uniteMessage.getBody().getPublicKey().toByteArray()), peer)), rendezvousPeers);
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

            pipeline.processInbound(address, addressedUniteMessage).join();

            verify(rendezvousPeers).add(any());

            pipeline.close();
        }

        @Test
        void shouldInitiateUniteForInboundMessageWithKnownSenderAndRecipient(@Mock final InetSocketAddressWrapper sender,
                                                                             @Mock(answer = RETURNS_DEEP_STUBS) final AddressedIntermediateEnvelope<MessageLite> message,
                                                                             @Mock(answer = RETURNS_DEEP_STUBS) final Peer senderPeer,
                                                                             @Mock(answer = RETURNS_DEEP_STUBS) final Peer recipientPeer) {
            final InetSocketAddressWrapper senderSocketAddress = new InetSocketAddressWrapper(80);
            final InetSocketAddressWrapper recipientSocketAddress = new InetSocketAddressWrapper(81);
            final CompressedPublicKey myKey = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
            final CompressedPublicKey senderKey = CompressedPublicKey.of("0364417e6f350d924b254deb44c0a6dce726876822c44c28ce221a777320041458");
            final CompressedPublicKey recipientKey = CompressedPublicKey.of("0229041b273dd5ee1c2bef2d77ae17dbd00d2f0a2e939e22d42ef1c4bf05147ea9");

            when(recipientPeer.isReachable(any())).thenReturn(true);
            when(senderPeer.getAddress()).thenReturn(senderSocketAddress);
            when(recipientPeer.getAddress()).thenReturn(recipientSocketAddress);
            when(identity.getPublicKey()).thenReturn(myKey);
            when(message.getContent().getSender()).thenReturn(senderKey);
            when(message.getContent().getRecipient()).thenReturn(recipientKey);

            final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, Map.of(message.getContent().getSender(), senderPeer, message.getContent().getRecipient(), recipientPeer), rendezvousPeers);
            final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
            final TestObserver<AddressedIntermediateEnvelope<?>> outboundMessages = pipeline.outboundMessages(new TypeReference<AddressedIntermediateEnvelope<?>>() {
            }).test();

            pipeline.processInbound(sender, message).join();

            outboundMessages.awaitCount(3)
                    .assertValueCount(3)
                    .assertValueAt(1, m -> m.getRecipient().equals(senderSocketAddress) && m.getContent().getPrivateHeader().getType() == UNITE)
                    .assertValueAt(2, m -> m.getRecipient().equals(recipientSocketAddress) && m.getContent().getPrivateHeader().getType() == UNITE);
            pipeline.close();
        }
    }

    @Nested
    class ApplicationTrafficRouting {
        @Nested
        class Inbound {
            @Test
            void shouldRelayMessageForKnownRecipient(@Mock(answer = RETURNS_DEEP_STUBS) final AddressedIntermediateEnvelope<MessageLite> message,
                                                     @Mock(answer = RETURNS_DEEP_STUBS) final Peer recipientPeer) {
                final Address sender = new InetSocketAddressWrapper(22527);
                when(recipientPeer.isReachable(any())).thenReturn(true);
                when(recipientPeer.getAddress()).thenReturn(new InetSocketAddressWrapper(25421));

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, Map.of(message.getContent().getRecipient(), recipientPeer), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<AddressedIntermediateEnvelope<?>> outboundMessages = pipeline.outboundMessages(new TypeReference<AddressedIntermediateEnvelope<?>>() {
                }).test();

                pipeline.processInbound(sender, message).join();

                outboundMessages.awaitCount(1)
                        .assertValueCount(1)
                        .assertValue(m -> m.getRecipient().equals(recipientPeer.getAddress()) && m.getContent().equals(message.getContent()));
                pipeline.close();
            }

            @Test
            void shouldCompleteExceptionallyOnInvalidMessage(@Mock final InetSocketAddressWrapper sender,
                                                             @Mock(answer = RETURNS_DEEP_STUBS) final AddressedIntermediateEnvelope<MessageLite> message,
                                                             @Mock(answer = RETURNS_DEEP_STUBS) final Peer recipientPeer,
                                                             @Mock(answer = RETURNS_DEEP_STUBS) final CompressedPublicKey recipient) throws InterruptedException {
                when(message.getContent().getRecipient()).thenThrow(IllegalArgumentException.class);
                when(message.refCnt()).thenReturn(1);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, Map.of(recipient, recipientPeer), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<Object> outboundMessages = pipeline.outboundMessages().test();

                assertThrows(ExecutionException.class, () -> pipeline.processInbound(sender, message).get());
                outboundMessages.await(1, SECONDS);
                outboundMessages.assertNoValues();
                pipeline.close();
            }

            @SuppressWarnings("SuspiciousMethodCalls")
            @Test
            void shouldUpdateLastCommunicationTimeAndConvertToApplicationMessageForRemoteApplicationMessages(
                    @Mock final Peer peer,
                    @Mock final InetSocketAddressWrapper address,
                    @Mock final InetSocketAddressWrapper senderAddress,
                    @Mock final InetSocketAddressWrapper recipientAddress) {
                final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
                final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
                final IntermediateEnvelope<Application> applicationMessage = IntermediateEnvelope.application(0, sender, ProofOfWork.of(6518542), recipient, byte[].class.getName(), new byte[]{});
                final AddressedIntermediateEnvelope<Application> addressedApplicationMessage = new AddressedIntermediateEnvelope<>(senderAddress, recipientAddress, applicationMessage);

                when(rendezvousPeers.contains(any())).thenReturn(true);
                when(identity.getPublicKey()).thenReturn(recipient);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(applicationMessage.getSender(), peer)), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<SerializedApplicationMessage> inboundMessages = pipeline.inboundMessages(SerializedApplicationMessage.class).test();

                pipeline.processInbound(address, addressedApplicationMessage).join();

                verify(peer).applicationTrafficOccurred();
                inboundMessages.awaitCount(1)
                        .assertValueCount(1);

                pipeline.close();
            }
        }

        @Nested
        class Outbound {
            @Test
            void shouldRelayMessageToKnowRecipient(@Mock final Peer recipientPeer) {
                final InetSocketAddressWrapper recipientSocketAddress = new InetSocketAddressWrapper(22527);
                final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
                final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
                final SerializedApplicationMessage message = new SerializedApplicationMessage(sender, recipient, byte[].class, "Hallo Welt".getBytes());

                when(recipientPeer.getAddress()).thenReturn(recipientSocketAddress);
                when(recipientPeer.isReachable(any())).thenReturn(true);
                when(identity.getPublicKey()).thenReturn(recipient);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, Map.of(recipient, recipientPeer), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<AddressedIntermediateEnvelope<?>> outboundMessages = pipeline.outboundMessages(new TypeReference<AddressedIntermediateEnvelope<?>>() {
                }).test();

                pipeline.processOutbound(recipient, message).join();

                outboundMessages.awaitCount(1)
                        .assertValueAt(0, m -> m.getRecipient().equals(recipientSocketAddress) && m.getContent().getPrivateHeader().getType() == APPLICATION);
                pipeline.close();
            }

            @Test
            void shouldRelayMessageToSuperPeerForUnknownRecipient(@Mock(answer = RETURNS_DEEP_STUBS) final Peer superPeerPeer) {
                final InetSocketAddressWrapper superPeerSocketAddress = new InetSocketAddressWrapper(22527);
                final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
                final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
                final SerializedApplicationMessage message = new SerializedApplicationMessage(sender, recipient, byte[].class, "Hallo Welt".getBytes());

                when(superPeerPeer.getAddress()).thenReturn(superPeerSocketAddress);
                when(peersManager.getSuperPeer()).thenReturn(recipient);
                when(identity.getPublicKey()).thenReturn(recipient);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, Map.of(recipient, superPeerPeer), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<AddressedIntermediateEnvelope<?>> outboundMessages = pipeline.outboundMessages(new TypeReference<AddressedIntermediateEnvelope<?>>() {
                }).test();

                pipeline.processOutbound(recipient, message).join();

                outboundMessages.awaitCount(1)
                        .assertValueCount(1)
                        .assertValue(m -> m.getRecipient().equals(superPeerSocketAddress) && m.getContent().getPrivateHeader().getType() == APPLICATION);
                pipeline.close();
            }

            @Test
            void shouldPassthroughForUnknownRecipientWhenNoSuperPeerIsPresent() {
                final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
                final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
                final SerializedApplicationMessage message = new SerializedApplicationMessage(sender, recipient, byte[].class, "Hallo Welt".getBytes());

                when(identity.getPublicKey()).thenReturn(sender);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, peers, rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);
                final TestObserver<IntermediateEnvelope<?>> outboundMessages = pipeline.outboundMessages(new TypeReference<IntermediateEnvelope<?>>() {
                }).test();

                pipeline.processOutbound(recipient, message).join();

                outboundMessages.awaitCount(1)
                        .assertValueCount(1)
                        .assertValue(m -> m.getRecipient().equals(recipient) && m.getPrivateHeader().getType() == APPLICATION);
                pipeline.close();
            }

            @SuppressWarnings("SuspiciousMethodCalls")
            @Test
            void shouldUpdateLastCommunicationTimeForApplicationMessages(@Mock final Peer peer) {
                final CompressedPublicKey sender = CompressedPublicKey.of("030e54504c1b64d9e31d5cd095c6e470ea35858ad7ef012910a23c9d3b8bef3f22");
                final CompressedPublicKey recipient = CompressedPublicKey.of("025e91733428b535e812fd94b0372c4bf2d52520b45389209acfd40310ce305ff4");
                final SerializedApplicationMessage message = new SerializedApplicationMessage(sender, recipient, byte[].class, "Hallo Welt".getBytes());

                when(rendezvousPeers.contains(any())).thenReturn(true);
                when(identity.getPublicKey()).thenReturn(recipient);

                final UdpDiscoveryHandler handler = new UdpDiscoveryHandler(openPingsCache, uniteAttemptsCache, new HashMap<>(Map.of(message.getRecipient(), peer)), rendezvousPeers);
                final EmbeddedPipeline pipeline = new EmbeddedPipeline(config, identity, peersManager, inboundSerialization, outboundSerialization, handler);

                pipeline.processOutbound(recipient, message).join();

                verify(peer).applicationTrafficOccurred();
                pipeline.close();
            }
        }
    }

    @Nested
    class TestPeer {
        private InetSocketAddressWrapper address;

        @BeforeEach
        void setUp() {
            address = new InetSocketAddressWrapper(22527);
        }

        @Nested
        class Getter {
            @Test
            void shouldReturnCorrectValues() {
                final long lastInboundControlTrafficTime = System.currentTimeMillis() - 1000;
                final long lastInboundPongTime = System.currentTimeMillis() - 100;
                final long lastApplicationTrafficTime = System.currentTimeMillis();
                final Peer peer = new Peer(address, lastInboundControlTrafficTime, lastInboundPongTime, lastApplicationTrafficTime);

                assertEquals(address, peer.getAddress());
                assertEquals(lastInboundControlTrafficTime, peer.getLastInboundControlTrafficTime());
                assertEquals(lastApplicationTrafficTime, peer.getLastApplicationTrafficTime());
            }
        }

        @Nested
        class InboundControlTrafficOccurred {
            @Test
            void shouldUpdateTime() {
                final long lastInboundControlTrafficTime = System.currentTimeMillis() - 1000;
                final long lastInboundPongTime = System.currentTimeMillis();
                final long lastApplicationTrafficTime = System.currentTimeMillis();
                final Peer peer = new Peer(address, lastInboundControlTrafficTime, lastInboundPongTime, lastApplicationTrafficTime);

                peer.inboundControlTrafficOccurred();

                assertThat(peer.getLastInboundControlTrafficTime(), greaterThan(lastInboundControlTrafficTime));
            }
        }

        @Nested
        class InboundPongOccurred {
            @Test
            void shouldNotFail() {
                final long lastInboundControlTrafficTime = System.currentTimeMillis();
                final long lastInboundPongTime = System.currentTimeMillis() - 1000;
                final long lastApplicationTrafficTime = System.currentTimeMillis();
                final Peer peer = new Peer(address, lastInboundControlTrafficTime, lastInboundPongTime, lastApplicationTrafficTime);

                assertDoesNotThrow(peer::inboundPongOccurred);
            }
        }

        @Nested
        class ApplicationTrafficOccurred {
            @Test
            void shouldUpdateTime() {
                final long lastInboundControlTrafficTime = System.currentTimeMillis();
                final long lastInboundPongTime = System.currentTimeMillis();
                final long lastApplicationTrafficTime = System.currentTimeMillis() - 1000;
                final Peer peer = new Peer(address, lastInboundControlTrafficTime, lastInboundPongTime, lastApplicationTrafficTime);

                peer.applicationTrafficOccurred();

                assertThat(peer.getLastApplicationTrafficTime(), greaterThan(lastApplicationTrafficTime));
            }
        }

        @Nested
        class HasApplicationTraffic {
            @Test
            void shouldReturnTrueIfTrafficIsPresent(@Mock final DrasylConfig config) {
                when(config.getRemotePingCommunicationTimeout()).thenReturn(ofSeconds(1));

                final Peer peer = new Peer(address, System.currentTimeMillis(), System.currentTimeMillis(), System.currentTimeMillis());

                assertTrue(peer.hasApplicationTraffic(config));
            }
        }

        @Nested
        class HasControlTraffic {
            @Test
            void shouldReturnTrueIfTrafficIsPresent(@Mock final DrasylConfig config) {
                when(config.getRemotePingTimeout()).thenReturn(ofSeconds(1));

                final Peer peer = new Peer(address, System.currentTimeMillis(), System.currentTimeMillis(), System.currentTimeMillis());

                assertTrue(peer.hasControlTraffic(config));
            }
        }

        @Nested
        class IsReachable {
            @Test
            void shouldReturnTrueIfPeerIsReachable(@Mock final DrasylConfig config) {
                when(config.getRemotePingTimeout()).thenReturn(ofSeconds(1));

                final Peer peer = new Peer(address, System.currentTimeMillis(), System.currentTimeMillis(), System.currentTimeMillis());
                assertTrue(peer.isReachable(config));
            }
        }
    }

    @Nested
    class TestOpenPing {
        private InetSocketAddressWrapper address;

        @BeforeEach
        void setUp() {
            address = new InetSocketAddressWrapper(22527);
        }

        @Nested
        class GetAddress {
            @Test
            void shouldReturnAddress() {
                final OpenPing ping = new OpenPing(address);

                assertEquals(address, ping.getAddress());
            }
        }

        @Nested
        class Equals {
            @SuppressWarnings("java:S2701")
            @Test
            void shouldRecognizeEqualPairs() {
                final OpenPing pingA = new OpenPing(address);
                final OpenPing pingB = new OpenPing(address);
                final OpenPing pingC = new OpenPing(new InetSocketAddressWrapper(25421));

                assertEquals(pingA, pingA);
                assertEquals(pingA, pingB);
                assertEquals(pingB, pingA);
                assertNotEquals(null, pingA);
                assertNotEquals(pingA, pingC);
                assertNotEquals(pingC, pingA);
            }
        }

        @Nested
        class HashCode {
            @Test
            void shouldRecognizeEqualPairs() {
                final OpenPing pingA = new OpenPing(address);
                final OpenPing pingB = new OpenPing(address);
                final OpenPing pingC = new OpenPing(new InetSocketAddressWrapper(25421));

                assertEquals(pingA.hashCode(), pingB.hashCode());
                assertNotEquals(pingA.hashCode(), pingC.hashCode());
                assertNotEquals(pingB.hashCode(), pingC.hashCode());
            }
        }

        @Test
        void toStringShouldReturnString() {
            final OpenPing ping = new OpenPing(address);

            assertNotNull(ping.toString());
        }
    }
}
