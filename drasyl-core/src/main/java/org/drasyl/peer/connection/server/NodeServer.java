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
package org.drasyl.peer.connection.server;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import org.drasyl.DrasylException;
import org.drasyl.DrasylNodeConfig;
import org.drasyl.identity.IdentityManager;
import org.drasyl.messenger.Messenger;
import org.drasyl.peer.PeersManager;
import org.drasyl.peer.connection.ConnectionsManager;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static org.drasyl.peer.connection.PeerConnection.CloseReason.REASON_SHUTTING_DOWN;
import static org.drasyl.util.UriUtil.overridePort;

@SuppressWarnings({ "squid:S00107" })
public class NodeServer implements AutoCloseable {
    public final EventLoopGroup workerGroup;
    public final EventLoopGroup bossGroup;
    public final ServerBootstrap serverBootstrap;
    private final IdentityManager identityManager;
    private final PeersManager peersManager;
    private final ConnectionsManager connectionsManager;
    private final DrasylNodeConfig config;
    private final Messenger messenger;
    private final AtomicBoolean opened;
    private Channel serverChannel;
    private NodeServerChannelBootstrap nodeServerChannelBootstrap;
    private int actualPort;
    private Set<URI> actualEndpoints;

    /**
     * Starts a node server for forwarding messages to child peers.<br> Default Port: 22527
     *
     * @param identityManager the identity manager
     * @param messenger       the messenger object
     * @param peersManager    the peers manager
     * @param workerGroup     netty shared worker group
     * @param bossGroup       netty shared boss group
     * @throws DrasylException if the loaded default config is invalid
     */
    public NodeServer(IdentityManager identityManager,
                      Messenger messenger,
                      PeersManager peersManager,
                      ConnectionsManager connectionsManager,
                      EventLoopGroup workerGroup,
                      EventLoopGroup bossGroup) throws DrasylException {
        this(identityManager, messenger, peersManager, connectionsManager, ConfigFactory.load(), workerGroup, bossGroup);
    }

    /**
     * Node server for forwarding messages to child peers.
     *
     * @param identityManager the identity manager
     * @param messenger       the messenger object
     * @param peersManager    the peers manager
     * @param config          config that should be used
     * @param workerGroup     netty shared worker group
     * @param bossGroup       netty shared boss group
     * @throws DrasylException if the given config is invalid
     */
    public NodeServer(IdentityManager identityManager,
                      Messenger messenger,
                      PeersManager peersManager,
                      ConnectionsManager connectionsManager,
                      Config config,
                      EventLoopGroup workerGroup,
                      EventLoopGroup bossGroup) throws DrasylException {
        this(identityManager, messenger, peersManager, connectionsManager, new DrasylNodeConfig(config), workerGroup, bossGroup);
    }

    /**
     * Node server for forwarding messages to child peers.
     *
     * @param identityManager the identity manager
     * @param messenger       the messenger object
     * @param peersManager    the peers manager
     * @param config          config that should be used
     * @param workerGroup     netty shared worker group
     * @param bossGroup       netty shared boss group
     */
    public NodeServer(IdentityManager identityManager,
                      Messenger messenger,
                      PeersManager peersManager,
                      ConnectionsManager connectionsManager,
                      DrasylNodeConfig config,
                      EventLoopGroup workerGroup,
                      EventLoopGroup bossGroup) throws NodeServerException {
        this(identityManager, messenger, peersManager, connectionsManager, config,
                null, new ServerBootstrap(),
                workerGroup, bossGroup,
                null, new AtomicBoolean(false), -1, new HashSet<>());

        nodeServerChannelBootstrap = new NodeServerChannelBootstrap(this, serverBootstrap, config);
    }

    NodeServer(IdentityManager identityManager,
               Messenger messenger,
               PeersManager peersManager,
               ConnectionsManager connectionsManager,
               DrasylNodeConfig config,
               Channel serverChannel,
               ServerBootstrap serverBootstrap,
               EventLoopGroup workerGroup,
               EventLoopGroup bossGroup,
               NodeServerChannelBootstrap nodeServerChannelBootstrap,
               AtomicBoolean opened,
               int actualPort,
               Set<URI> actualEndpoints) {
        this.identityManager = identityManager;
        this.peersManager = peersManager;
        this.connectionsManager = connectionsManager;
        this.config = config;
        this.serverChannel = serverChannel;
        this.serverBootstrap = serverBootstrap;
        this.workerGroup = workerGroup;
        this.bossGroup = bossGroup;
        this.nodeServerChannelBootstrap = nodeServerChannelBootstrap;
        this.opened = opened;
        this.messenger = messenger;
        this.actualPort = actualPort;
        this.actualEndpoints = actualEndpoints;
    }

    public ConnectionsManager getConnectionsManager() {
        return connectionsManager;
    }

    public Messenger getMessenger() {
        return messenger;
    }

    /**
     * @return the peers manager
     */
    public PeersManager getPeersManager() {
        return peersManager;
    }

    /**
     * @return the entry points
     */
    public Set<URI> getEntryPoints() {
        return actualEndpoints;
    }

    /**
     * @return the config
     */
    public DrasylNodeConfig getConfig() {
        return config;
    }

    EventLoopGroup getBossGroup() {
        return bossGroup;
    }

    EventLoopGroup getWorkerGroup() {
        return workerGroup;
    }

    public boolean isOpen() {
        return opened.get();
    }

    public IdentityManager getIdentityManager() {
        return identityManager;
    }

    /**
     * Starts the relay server.
     */
    public void open() throws NodeServerException {
        if (opened.compareAndSet(false, true)) {
            serverChannel = nodeServerChannelBootstrap.getChannel();

            InetSocketAddress socketAddress = (InetSocketAddress) serverChannel.localAddress();
            actualPort = socketAddress.getPort();
            actualEndpoints = config.getServerEndpoints().stream()
                    .map(uri -> {
                        if (uri.getPort() == 0) {
                            return overridePort(uri, getPort());
                        }
                        return uri;
                    }).collect(Collectors.toSet());
        }
    }

    /**
     * Returns the actual bind port used by this server.
     */
    public int getPort() {
        return actualPort;
    }

    /**
     * Closes the server socket and all open client sockets.
     */
    @Override
    public void close() {
        if (opened.compareAndSet(true, false)) {
            // update peer information
            peersManager.unsetSuperPeer();

            connectionsManager.closeConnectionsOfType(NodeServerConnection.class, REASON_SHUTTING_DOWN);

            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close().syncUninterruptibly();
            }
        }
    }
}
