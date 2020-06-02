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
package org.drasyl.peer.connection.superpeer;

import com.typesafe.config.ConfigFactory;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.reactivex.rxjava3.observers.TestObserver;
import io.reactivex.rxjava3.subjects.ReplaySubject;
import io.reactivex.rxjava3.subjects.Subject;
import org.drasyl.DrasylException;
import org.drasyl.DrasylNodeConfig;
import org.drasyl.event.Event;
import org.drasyl.event.Node;
import org.drasyl.identity.IdentityManager;
import org.drasyl.identity.IdentityManagerException;
import org.drasyl.messenger.Messenger;
import org.drasyl.peer.PeersManager;
import org.drasyl.peer.connection.ConnectionsManager;
import org.drasyl.peer.connection.message.*;
import org.drasyl.peer.connection.server.NodeServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import testutils.AnsiColor;
import testutils.TestHelper;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.drasyl.event.EventType.EVENT_NODE_OFFLINE;
import static org.drasyl.event.EventType.EVENT_NODE_ONLINE;
import static org.drasyl.peer.connection.PeerConnection.CloseReason.REASON_SHUTTING_DOWN;
import static org.drasyl.peer.connection.message.StatusMessage.Code.STATUS_OK;

@Execution(ExecutionMode.SAME_THREAD)
class SuperPeerClientIT {
    public static final long TIMEOUT = 10000L;
    DrasylNodeConfig config;
    DrasylNodeConfig serverConfig;
    private EventLoopGroup workerGroup;
    private EventLoopGroup bossGroup;
    private IdentityManager identityManager;
    private IdentityManager identityManagerServer;
    private NodeServer server;
    private Messenger messenger;
    private PeersManager peersManager;
    private Subject<Event> emittedEventsSubject;
    private ConnectionsManager connectionsManager;

    @BeforeEach
    void setup(TestInfo info) throws DrasylException {
        TestHelper.colorizedPrintln("STARTING " + info.getDisplayName(), AnsiColor.COLOR_CYAN, AnsiColor.STYLE_REVERSED);

        System.setProperty("io.netty.tryReflectionSetAccessible", "true");

        workerGroup = new NioEventLoopGroup();
        bossGroup = new NioEventLoopGroup(1);

        config = new DrasylNodeConfig(ConfigFactory.load("configs/SuperPeerClientIT.conf"));
        identityManager = new IdentityManager(config);
        identityManager.loadOrCreateIdentity();

        serverConfig = new DrasylNodeConfig(ConfigFactory.load("configs/SuperPeerClientIT-NodeServer.conf"));
        identityManagerServer = new IdentityManager(serverConfig);
        identityManagerServer.loadOrCreateIdentity();
        peersManager = new PeersManager();
        connectionsManager = new ConnectionsManager(event -> {
        });
        messenger = new Messenger(connectionsManager);

        server = new NodeServer(identityManagerServer, messenger, peersManager, connectionsManager, serverConfig, workerGroup, bossGroup);
        server.open();
        emittedEventsSubject = ReplaySubject.create();
    }

    @AfterEach
    void cleanUp(TestInfo info) throws IdentityManagerException {
        server.close();

        IdentityManager.deleteIdentityFile(config.getIdentityPath());
        workerGroup.shutdownGracefully().syncUninterruptibly();
        bossGroup.shutdownGracefully().syncUninterruptibly();
        TestHelper.colorizedPrintln("FINISHED " + info.getDisplayName(), AnsiColor.COLOR_CYAN, AnsiColor.STYLE_REVERSED);
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldSendJoinMessageOnConnect() throws SuperPeerClientException {
        TestObserver<Message> receivedMessages = IntegrationTestHandler.receivedMessages().test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, event -> {
        });
        client.open(server.getEntryPoints());

        // verify received messages
        receivedMessages.awaitCount(1);
        receivedMessages.assertValueAt(0, new JoinMessage(identityManager.getIdentity().getPublicKey(), server.getEntryPoints()));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldSendQuitMessageOnClientSideDisconnect() throws SuperPeerClientException {
        TestObserver<Message> receivedMessages = IntegrationTestHandler.receivedMessages().test();
        TestObserver<Event> emittedEvents = emittedEventsSubject.test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, emittedEventsSubject::onNext);
        client.open(server.getEntryPoints());

        // wait for node to become online, before closing it
        emittedEvents.awaitCount(1);
        client.close();

        // verify emitted events
        receivedMessages.awaitCount(3);
        receivedMessages.assertValueAt(2, new QuitMessage(REASON_SHUTTING_DOWN));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldEmitNodeOfflineEventOnClientSideDisconnect() throws SuperPeerClientException {
        TestObserver<Event> emittedEvents = emittedEventsSubject.test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, emittedEventsSubject::onNext);
        client.open(server.getEntryPoints());

        // wait for node to become online, before closing it
        emittedEvents.awaitCount(1);
        client.close();

        // verify emitted events
        emittedEvents.awaitCount(2);
        emittedEvents.assertValueAt(1, new Event(EVENT_NODE_OFFLINE, Node.of(identityManager.getAddress())));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldRespondToPingMessageWithPongMessage() throws SuperPeerClientException {
        TestObserver<Message> sentMessages = IntegrationTestHandler.sentMessages().test();
        TestObserver<Message> receivedMessages = IntegrationTestHandler.receivedMessages().filter(m -> m instanceof PongMessage).test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, event -> {
        });
        client.open(server.getEntryPoints());
        sentMessages.awaitCount(1);

        // send message
        PingMessage request = new PingMessage();
        IntegrationTestHandler.injectMessage(request);

        // verify received message
        receivedMessages.awaitCount(1);
        receivedMessages.assertValueAt(0, new PongMessage(request.getId()));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldRespondToApplicationMessageWithStatusOk() throws SuperPeerClientException {
        TestObserver<Message> sentMessages = IntegrationTestHandler.sentMessages().test();
        TestObserver<Message> receivedMessages = IntegrationTestHandler.receivedMessages().filter(m -> m instanceof StatusMessage).test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, event -> {
        });
        client.open(server.getEntryPoints());
        sentMessages.awaitCount(1);

        // send message
        ApplicationMessage request = new ApplicationMessage(TestHelper.random(), identityManager.getAddress(), new byte[]{
                0x00,
                0x01
        });
        IntegrationTestHandler.injectMessage(request);

        // verify received message
        receivedMessages.awaitCount(2);
        receivedMessages.assertValueAt(1, new StatusMessage(STATUS_OK, request.getId()));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldEmitNodeOfflineEventAfterReceivingQuitMessage() throws SuperPeerClientException {
        TestObserver<Message> receivedMessages = IntegrationTestHandler.receivedMessages().test();
        TestObserver<Event> emittedEvents = emittedEventsSubject.filter(e -> e.getType() == EVENT_NODE_OFFLINE).test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, emittedEventsSubject::onNext);
        client.open(server.getEntryPoints());
        receivedMessages.awaitCount(1);

        // send message
        IntegrationTestHandler.injectMessage(new QuitMessage());

        // verify emitted events
        emittedEvents.awaitCount(1);
        emittedEvents.assertValue(new Event(EVENT_NODE_OFFLINE, Node.of(identityManager.getAddress())));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldEmitNodeOnlineEventAfterReceivingWelcomeMessage() throws SuperPeerClientException {
        TestObserver<Event> emittedEvents = emittedEventsSubject.test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, emittedEventsSubject::onNext);
        client.open(server.getEntryPoints());

        // verify emitted events
        emittedEvents.awaitCount(1);
        emittedEvents.assertValue(new Event(EVENT_NODE_ONLINE, new Node(identityManager.getAddress())));
    }

    @Test
    @Timeout(value = TIMEOUT, unit = MILLISECONDS)
    void clientShouldReconnectOnDisconnect() throws SuperPeerClientException {
        TestObserver<Event> emittedEvents = emittedEventsSubject.test();

        // start client
        SuperPeerClient client = new SuperPeerClient(config, identityManager, peersManager, messenger, workerGroup, connectionsManager, emittedEventsSubject::onNext);
        client.open(server.getEntryPoints());

        emittedEvents.awaitCount(1);
        // TODO: initiate disconnect from Server?
        client.close();
        client.open(server.getEntryPoints());

        // verify emitted events
        emittedEvents.awaitCount(3);
        emittedEvents.assertValues(
                new Event(EVENT_NODE_ONLINE, new Node(identityManager.getAddress())),
                new Event(EVENT_NODE_OFFLINE, new Node(identityManager.getAddress())),
                new Event(EVENT_NODE_ONLINE, new Node(identityManager.getAddress()))
        );
    }
}
