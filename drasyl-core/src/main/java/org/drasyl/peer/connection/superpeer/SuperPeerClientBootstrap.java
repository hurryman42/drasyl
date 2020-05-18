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

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.drasyl.DrasylNodeConfig;
import org.drasyl.util.WebsocketUtil;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.concurrent.ExecutionException;

public class SuperPeerClientBootstrap {
    private final DrasylNodeConfig config;
    private final EventLoopGroup workerGroup;
    private final URI endpoint;
    private final SuperPeerClientInitializer superPeerClientInitializer;
    private final SuperPeerClient superPeerClient;

    public SuperPeerClientBootstrap(DrasylNodeConfig config,
                                    EventLoopGroup workerGroup,
                                    URI endpoint,
                                    SuperPeerClient superPeerClient) throws SuperPeerClientException {
        this.config = config;
        this.workerGroup = workerGroup;
        this.endpoint = endpoint;
        this.superPeerClient = superPeerClient;
        String channelInitializer = config.getSuperPeerChannelInitializer();

        try {
            this.superPeerClientInitializer = getChannelInitializer(channelInitializer);
        }
        catch (ClassNotFoundException e) {
            throw new SuperPeerClientException("The given channel initializer can't be found: '" + channelInitializer + "'");
        }
        catch (NoSuchMethodException e) {
            throw new SuperPeerClientException("The given channel initializer has not the correct signature: '" + channelInitializer + "'");
        }
        catch (IllegalAccessException e) {
            throw new SuperPeerClientException("Can't access the given channel initializer: '" + channelInitializer + "'");
        }
        catch (InvocationTargetException e) {
            throw new SuperPeerClientException("Can't invoke the given channel initializer: '" + channelInitializer + "'");
        }
        catch (InstantiationException e) {
            throw new SuperPeerClientException("Can't instantiate the given channel initializer: '" + channelInitializer + "'");
        }
    }

    private SuperPeerClientInitializer getChannelInitializer(String className) throws ClassNotFoundException,
            NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Class<?> c = Class.forName(className);
        Constructor<?> cons = c.getConstructor(DrasylNodeConfig.class, URI.class, SuperPeerClient.class);

        return (SuperPeerClientInitializer) cons.newInstance(config, endpoint, superPeerClient);
    }

    public Channel getChannel() throws SuperPeerClientException {
        ChannelFuture channelFuture = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                .handler(superPeerClientInitializer)
                .connect(endpoint.getHost(), WebsocketUtil.websocketPort(endpoint));
        channelFuture.awaitUninterruptibly();

        if (channelFuture.isSuccess()) {
            Channel channel = channelFuture.channel();

            try {
                superPeerClientInitializer.connectedFuture().get();

                return channel;
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            catch (ExecutionException e) {
                throw new SuperPeerClientException(e.getCause());
            }
        }
        else {
            throw new SuperPeerClientException(channelFuture.cause());
        }
    }
}
