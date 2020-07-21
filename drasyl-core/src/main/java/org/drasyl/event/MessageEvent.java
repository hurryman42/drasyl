package org.drasyl.event;

import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.util.Pair;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * This event signals that the node has received a message addressed to it.
 */
public class MessageEvent implements Event {
    private final Pair<CompressedPublicKey, Object> message;

    public MessageEvent(Pair<CompressedPublicKey, Object> message) {
        this.message = requireNonNull(message);
    }

    /**
     * @return a pair containing the sender's public key as first element and the message payload as
     * second element.
     */
    public Pair<CompressedPublicKey, Object> getMessage() {
        return message;
    }

    @Override
    public int hashCode() {
        return Objects.hash(message);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MessageEvent that = (MessageEvent) o;
        return Objects.equals(message, that.message);
    }

    @Override
    public String toString() {
        return "MessageEvent{" +
                "message=" + message +
                '}';
    }
}
