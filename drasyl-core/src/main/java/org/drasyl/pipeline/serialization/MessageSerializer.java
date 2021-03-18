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
package org.drasyl.pipeline.serialization;

import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Stateless;
import org.drasyl.pipeline.skeleton.SimpleDuplexHandler;
import org.drasyl.serialization.Serializer;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

/**
 * This handler serializes messages to byte array an vice vera.
 */
@Stateless
@SuppressWarnings({ "java:S110" })
public final class MessageSerializer extends SimpleDuplexHandler<SerializedApplicationMessage, Object, CompressedPublicKey> {
    public static final MessageSerializer INSTANCE = new MessageSerializer();
    public static final String MESSAGE_SERIALIZER = "MESSAGE_SERIALIZER";
    private static final Logger LOG = LoggerFactory.getLogger(MessageSerializer.class);

    private MessageSerializer() {
        // singleton
    }

    @Override
    protected void matchedInbound(final HandlerContext ctx,
                                  final CompressedPublicKey sender,
                                  final SerializedApplicationMessage msg,
                                  final CompletableFuture<Void> future) {
        try {
            final Serializer serializer = ctx.inboundSerialization().findSerializerFor(msg.getType());

            if (serializer != null) {
                final Object o = serializer.fromByteArray(msg.getContent(), msg.getType());

                ctx.passInbound(sender, o, future);
                LOG.trace("Message has been deserialized to '{}'", () -> o);
            }
            else {
                LOG.warn("No serializer was found for type '{}'. You can find more information regarding this here: https://docs.drasyl.org/configuration/serialization/", msg::getType);
                future.completeExceptionally(new Exception("No serializer was found for type '" + msg.getType() + "'. You can find more information regarding this here: https://docs.drasyl.org/configuration/serialization/"));
            }
        }
        catch (final IOException | IllegalArgumentException e) {
            LOG.warn("Deserialization of '{}' failed:", () -> msg, () -> e);
            future.completeExceptionally(new Exception("Deserialization failed", e));
        }
    }

    @Override
    protected void matchedOutbound(final HandlerContext ctx,
                                   final CompressedPublicKey recipient,
                                   final Object msg,
                                   final CompletableFuture<Void> future) {
        try {
            final Serializer serializer = ctx.outboundSerialization().findSerializerFor(msg != null ? msg.getClass().getName() : null);

            final String type;
            if (msg != null) {
                type = msg.getClass().getName();
            }
            else {
                type = null;
            }

            if (serializer != null) {
                final byte[] bytes = serializer.toByteArray(msg);
                final SerializedApplicationMessage serializedMsg = new SerializedApplicationMessage(null, recipient, type, bytes);
                ctx.passOutbound(recipient, serializedMsg, future);
                LOG.trace("Message has been serialized to '{}'", () -> serializedMsg);
            }
            else {
                LOG.warn("No serializer was found for type '{}'. You can find more information regarding this here: https://docs.drasyl.org/configuration/serialization/", type);
                future.completeExceptionally(new Exception("No serializer was found for type '" + type + "'. You can find more information regarding this here: https://docs.drasyl.org/configuration/serialization/"));
            }
        }
        catch (final IOException e) {
            LOG.warn("Serialization of '{}' failed:", () -> msg, () -> e);
            future.completeExceptionally(new Exception("Deserialization failed", e));
        }
    }
}
