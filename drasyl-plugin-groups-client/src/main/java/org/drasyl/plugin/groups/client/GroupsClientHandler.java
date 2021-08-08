/*
 * Copyright (c) 2020-2021 Heiko Bornholdt and Kevin Röbert
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
package org.drasyl.plugin.groups.client;

import io.netty.channel.ChannelHandlerContext;
import io.netty.util.concurrent.Future;
import org.drasyl.channel.MigrationEvent;
import org.drasyl.channel.MigrationOutboundMessage;
import org.drasyl.event.Event;
import org.drasyl.event.NodeUpEvent;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.pipeline.address.Address;
import org.drasyl.pipeline.skeleton.SimpleInboundHandler;
import org.drasyl.plugin.groups.client.event.GroupJoinFailedEvent;
import org.drasyl.plugin.groups.client.event.GroupJoinedEvent;
import org.drasyl.plugin.groups.client.event.GroupLeftEvent;
import org.drasyl.plugin.groups.client.event.GroupMemberJoinedEvent;
import org.drasyl.plugin.groups.client.event.GroupMemberLeftEvent;
import org.drasyl.plugin.groups.client.message.GroupJoinFailedMessage;
import org.drasyl.plugin.groups.client.message.GroupJoinMessage;
import org.drasyl.plugin.groups.client.message.GroupLeaveMessage;
import org.drasyl.plugin.groups.client.message.GroupWelcomeMessage;
import org.drasyl.plugin.groups.client.message.GroupsClientMessage;
import org.drasyl.plugin.groups.client.message.GroupsServerMessage;
import org.drasyl.plugin.groups.client.message.MemberJoinedMessage;
import org.drasyl.plugin.groups.client.message.MemberLeftMessage;
import org.drasyl.serialization.JacksonJsonSerializer;
import org.drasyl.util.FutureCombiner;
import org.drasyl.util.FutureUtil;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.drasyl.channel.DefaultDrasylServerChannel.IDENTITY_ATTR_KEY;
import static org.drasyl.channel.DefaultDrasylServerChannel.INBOUND_SERIALIZATION_ATTR_KEY;
import static org.drasyl.channel.DefaultDrasylServerChannel.OUTBOUND_SERIALIZATION_ATTR_KEY;

public class GroupsClientHandler extends SimpleInboundHandler<GroupsServerMessage, Address> {
    private static final Logger LOG = LoggerFactory.getLogger(GroupsClientHandler.class);
    private static final Duration RETRY_DELAY = Duration.ofSeconds(10);
    private static final Duration FIRST_JOIN_DELAY = Duration.ofSeconds(5);
    private final Duration firstJoinDelay;
    private final Map<Group, GroupUri> groups;
    private final Map<Group, Future> renewTasks;

    @SuppressWarnings("java:S2384")
    GroupsClientHandler(final Map<Group, GroupUri> groups,
                        final Map<Group, Future> renewTasks,
                        final Duration firstJoinDelay) {
        this.groups = requireNonNull(groups);
        this.renewTasks = requireNonNull(renewTasks);
        this.firstJoinDelay = requireNonNull(firstJoinDelay);
    }

    public GroupsClientHandler(final Set<GroupUri> groups) {
        this(groups.stream().collect(Collectors.toMap(GroupUri::getGroup, groupURI -> groupURI)),
                new ConcurrentHashMap<>(), FIRST_JOIN_DELAY);
    }

    @Override
    protected void matchedInbound(final ChannelHandlerContext ctx,
                                  final Address sender,
                                  final GroupsServerMessage msg,
                                  final CompletableFuture<Void> future) {
        if (msg instanceof MemberJoinedMessage) {
            onMemberJoined(ctx, (MemberJoinedMessage) msg, future);
        }
        else if (msg instanceof MemberLeftMessage) {
            onMemberLeft(ctx, (MemberLeftMessage) msg, future);
        }
        else if (msg instanceof GroupWelcomeMessage) {
            onWelcome(ctx, sender, (GroupWelcomeMessage) msg, future);
        }
        else if (msg instanceof GroupJoinFailedMessage) {
            onJoinFailed(ctx, (GroupJoinFailedMessage) msg, future);
        }
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) {
        ctx.attr(INBOUND_SERIALIZATION_ATTR_KEY).get().addSerializer(GroupsServerMessage.class, new JacksonJsonSerializer());
        ctx.attr(OUTBOUND_SERIALIZATION_ATTR_KEY).get().addSerializer(GroupsClientMessage.class, new JacksonJsonSerializer());
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        // Stop all renew tasks
        for (final Future renewTask : renewTasks.values()) {
            renewTask.cancel(false);
        }
        renewTasks.clear();

        /*
         * Leave all groups.
         * This should be a blocking operation, so drasyl is not shutting down the communication
         * channel before the leave messages are sent.
         */
        for (final Entry<Group, GroupUri> entry : groups.entrySet()) {
            final Group group = entry.getKey();
            final GroupUri groupURI = entry.getValue();
            try {
                final CompletableFuture<Void> future = new CompletableFuture<>();
                FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) new GroupLeaveMessage(group), (Address) groupURI.getManager())))).combine(future);
                future.get();
            }
            catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                LOG.warn("Exception occurred during de-registration from group `{}`: ", group.getName(), e);
            }
            catch (final ExecutionException e) {
                LOG.warn("Exception occurred during de-registration from group `{}`: ", group.getName(), e);
            }
        }
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx,
                                   final Object evt) {
        if (evt instanceof MigrationEvent) {
            final Event event = ((MigrationEvent) evt).event();
            if (event instanceof NodeUpEvent) {
                // join every group but we will wait 5 seconds, to give it the chance to connect to some super peer if needed
                ctx.executor().schedule(() -> groups.values().forEach(group ->
                        joinGroup(ctx, group, false)), firstJoinDelay.toMillis(), MILLISECONDS);
            }
        }

        ctx.fireUserEventTriggered(evt);
    }

    /**
     * Will be executed on {@link MemberJoinedMessage}.
     *
     * @param ctx    the handling context
     * @param msg    the member joined message
     * @param future the message future
     */
    private static void onMemberJoined(final ChannelHandlerContext ctx,
                                       final MemberJoinedMessage msg,
                                       final CompletableFuture<Void> future) {
        final CompletableFuture<Void> future1 = new CompletableFuture<>();
        ctx.fireUserEventTriggered(new MigrationEvent(GroupMemberJoinedEvent.of(msg.getMember(), msg.getGroup()), future1));
        FutureCombiner.getInstance()
                .add(future1)
                .combine(future);
    }

    /**
     * Will be executed on {@link GroupJoinFailedMessage}.
     *
     * @param ctx    the handling context
     * @param msg    the join failed message
     * @param future the message future
     */
    private void onJoinFailed(final ChannelHandlerContext ctx,
                              final GroupJoinFailedMessage msg,
                              final CompletableFuture<Void> future) {
        final Group group = msg.getGroup();

        // cancel renew task
        final Future disposable = renewTasks.remove(group);
        if (disposable != null) {
            disposable.cancel(false);
        }

        final CompletableFuture<Void> future1 = new CompletableFuture<>();
        ctx.fireUserEventTriggered(new MigrationEvent(GroupJoinFailedEvent.of(group, msg.getReason(),
                () -> joinGroup(ctx, groups.get(group), false)), future1));
        FutureCombiner.getInstance()
                .add(future1)
                .combine(future);
    }

    /**
     * Will be executed on {@link MemberLeftMessage}.
     *
     * @param ctx    the handling context
     * @param msg    the member left message
     * @param future the message future
     */
    private void onMemberLeft(final ChannelHandlerContext ctx,
                              final MemberLeftMessage msg,
                              final CompletableFuture<Void> future) {
        final Group group = msg.getGroup();

        if (msg.getMember().equals(ctx.attr(IDENTITY_ATTR_KEY).get().getIdentityPublicKey())) {
            // cancel renew task
            final Future disposable = renewTasks.remove(group);
            if (disposable != null) {
                disposable.cancel(false);
            }

            final CompletableFuture<Void> future1 = new CompletableFuture<>();
            ctx.fireUserEventTriggered(new MigrationEvent(GroupLeftEvent.of(group, () -> joinGroup(ctx, groups.get(group), false)), future1));
            FutureCombiner.getInstance()
                    .add(future1)
                    .combine(future);
        }
        else {
            final CompletableFuture<Void> future1 = new CompletableFuture<>();
            ctx.fireUserEventTriggered(new MigrationEvent(GroupMemberLeftEvent.of(msg.getMember(), group), future1));
            FutureCombiner.getInstance()
                    .add(future1)
                    .combine(future);
        }
    }

    /**
     * Will be executed on {@link GroupWelcomeMessage}.
     *
     * @param ctx    the handling context
     * @param sender the sender (group manager)
     * @param msg    the welcome message
     * @param future the message future
     */
    private void onWelcome(final ChannelHandlerContext ctx,
                           final Address sender,
                           final GroupWelcomeMessage msg,
                           final CompletableFuture<Void> future) {
        final Group group = msg.getGroup();
        final Duration timeout = groups.get(group).getTimeout();

        // replace old re-try task with renew task
        final Future disposable = renewTasks.remove(group);
        if (disposable != null) {
            disposable.cancel(false);
        }

        // Add renew task
        renewTasks.put(group, ctx.executor().scheduleAtFixedRate(() ->
                joinGroup(ctx, groups.get(group), true), timeout.dividedBy(2).toMillis(), timeout.dividedBy(2).toMillis(), MILLISECONDS));

        final CompletableFuture<Void> future1 = new CompletableFuture<>();
        ctx.fireUserEventTriggered(new MigrationEvent(GroupJoinedEvent.of(
                group,
                msg.getMembers(),
                () -> FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) new GroupLeaveMessage(group), sender)))).combine(new CompletableFuture<Void>())), future1));
        FutureCombiner.getInstance()
                .add(future1)
                .combine(future);
    }

    /**
     * Joins the given {@code group}.
     *
     * @param ctx   the handler context
     * @param group the group to join
     * @param renew if this is a renew message or not
     */
    private void joinGroup(final ChannelHandlerContext ctx,
                           final GroupUri group,
                           final boolean renew) {
        final ProofOfWork proofOfWork = ctx.attr(IDENTITY_ATTR_KEY).get().getProofOfWork();
        final IdentityPublicKey groupManager = group.getManager();

        FutureCombiner.getInstance().add(FutureUtil.toFuture(ctx.writeAndFlush(new MigrationOutboundMessage<>((Object) new GroupJoinMessage(group.getGroup(), group.getCredentials(), proofOfWork, renew), (Address) groupManager)))).combine(new CompletableFuture<Void>());

        // Add re-try task
        if (!renewTasks.containsKey(group.getGroup())) {
            renewTasks.put(group.getGroup(), ctx.executor().scheduleAtFixedRate(() ->
                    joinGroup(ctx, groups.get(group.getGroup()), false), RETRY_DELAY.toMillis(), RETRY_DELAY.toMillis(), MILLISECONDS));
        }

        LOG.debug("Send join (renew={}) request for group `{}`", () -> renew, () -> group);
    }
}
