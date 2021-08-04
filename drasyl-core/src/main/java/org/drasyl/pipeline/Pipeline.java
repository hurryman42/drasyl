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
package org.drasyl.pipeline;

import org.drasyl.event.Event;
import org.drasyl.pipeline.address.Address;
import org.drasyl.util.scheduler.DrasylSchedulerUtil;

import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

/**
 * A list of {@link Handler}s which handles or intercepts inbound events and outbound operations of
 * a {@link org.drasyl.DrasylNode}. {@link Pipeline} implements an advanced form of the
 * <a href="http://www.oracle.com/technetwork/java/interceptingfilter-142169.html">Intercepting
 * Filter</a> pattern to give a user full control over how an event is handled and how the {@link
 * Handler}s in a pipeline interact with each other. This implementation is very closely based on
 * the netty implementation.
 *
 * <h3>Creation of a pipeline</h3>
 * <p>
 * Each per DrasylNode exists one pipeline and it is created automatically when a new node is
 * created.
 *
 * <h3>How an event flows in a pipeline</h3>
 * <p>
 * The following diagram describes how I/O events are processed by {@link Handler}s in a {@link
 * Pipeline} typically. An I/O event are handled by a {@link Handler}  and be forwarded to its
 * closest handler by calling the event propagation methods defined in {@link HandlerContext}, such
 * as {@link HandlerContext#passInbound(Address, Object, CompletableFuture)} and {@link
 * HandlerContext#passOutbound(Address, Object, CompletableFuture)} .
 *
 * <pre>
 *                                                 I/O Request
 *                                            via {@link HandlerContext}
 *                                                      |
 *  +---------------------------------------------------+---------------+
 *  |                            Pipeline               |               |
 *  |                                                  \|/              |
 *  |    +---------------------+            +-----------+----------+    |
 *  |    |      Handler  N     |            |       Handler  1     |    |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |              /|\                                  |               |
 *  |               |                                  \|/              |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |    |      Handler N-1    |            |       Handler  2     |    |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |              /|\                                  .               |
 *  |               .                                   .               |
 *  |   HandlerContext.fireIN_EVT()          HandlerContext.OUT_EVT()   |
 *  |        [method call]                        [method call]         |
 *  |               .                                   .               |
 *  |               .                                  \|/              |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |    |      Handler  2     |            |       Handler M-1    |    |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |              /|\                                  |               |
 *  |               |                                  \|/              |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |    |      Handler  1     |            |       Handler  M     |    |
 *  |    +----------+----------+            +-----------+----------+    |
 *  |              /|\                                  |               |
 *  +---------------+-----------------------------------+---------------+
 *                  |                                  \|/
 *  +---------------+-----------------------------------+---------------+
 *  |               |                                   |               |
 *  |   [ DrasylNodeComponent ]              [ MessageSink.send() ]     |
 *  |                                                                   |
 *  |  drasyl internal I/O                                              |
 *  +-------------------------------------------------------------------+
 *  </pre>
 * <p>
 * An inbound event is handled by the handlers in the bottom-up direction as shown on the left side
 * of the diagram. A handler usually handles the inbound data generated by the I/O thread on the
 * bottom of the diagram. The inbound data is often read from a remote peer via the actual input
 * operation. If an inbound event goes beyond the top handler, it is passed to the application.
 * <p>
 * An outbound event is handled by the handler in the top-down direction as shown on the right side
 * of the diagram. A handler usually generates or transforms the outbound traffic such as write
 * requests.
 * <p>
 * For example, let us assume that we created the following pipeline:
 * <pre>
 * {@link Pipeline} p = ...;
 * p.addLast("1", new HandlerA());
 * p.addLast("2", new HandlerB());
 * p.addLast("3", new HandlerC());
 * p.addLast("4", new HandlerD());
 * p.addLast("5", new HandlerE());
 * </pre>
 * In the given example configuration, the handler evaluation order is 1, 2, 3, 4, 5 when an event
 * goes inbound. When an event goes outbound, the order is 5, 4, 3, 2, 1.
 *
 * <h3>Forwarding an event to the next handler</h3>
 * <p>
 * As you might noticed in the diagram, a handler has to invoke the event propagation methods in
 * {@link HandlerContext} to forward an event to its next handler. Those methods include:
 * <ul>
 * <li>Inbound event propagation methods:
 *     <ul>
 *     <li>{@link HandlerContext#passInbound(Address, Object, CompletableFuture)}</li>
 *     <li>{@link HandlerContext#passEvent(Event, CompletableFuture)}</li>
 *     <li>{@link HandlerContext#passException(Exception)}</li>
 *     </ul>
 * </li>
 * <li>Outbound event propagation methods:
 *     <ul>
 *     <li>{@link HandlerContext#passOutbound(Address, Object, CompletableFuture)} </li>
 *     </ul>
 * </li>
 * </ul>
 *
 * <h3>Thread safety</h3>
 * <p>
 * A {@link Handler} can be added or removed at any time because a {@link Pipeline} is thread safe.
 *
 * <li>But for every invocation of:
 *       <ul>
 *       <li>{@link Pipeline#processInbound(Address, Object)}</li>
 *       <li>{@link Pipeline#processInbound(Event)}</li>
 *       <li>{@link Pipeline#processOutbound(Address, Object)}</li>
 *       </ul>
 * </li>
 * the invocation is scheduled in the {@link DrasylSchedulerUtil}, therefore the order of
 * invocations can't be guaranteed. You have to ensure by yourself, that your handlers are thread-safe
 * if you need it. Also, you have to ensure the order of messages, if you need it.
 */
@SuppressWarnings("UnusedReturnValue")
public interface Pipeline {
    /**
     * Appends a {@link Handler} at the last position of this pipeline.
     *
     * @param name    the name of the handler to append
     * @param handler the handler to append
     * @throws IllegalArgumentException if there's an entry with the same name already in the
     *                                  pipeline
     * @throws NullPointerException     if the specified handler is {@code null}
     */
    Pipeline addLast(String name, Handler handler);

    /**
     * Removes the {@link Handler} with the specified name from this pipeline.
     *
     * @param name the name under which the {@link Handler} was stored.
     * @throws NoSuchElementException if there's no such handler with the specified name in this
     *                                pipeline
     * @throws NullPointerException   if the specified name is {@code null}
     */
    Pipeline remove(String name);

    /**
     * Processes an inbound message by the pipeline.
     * <p>
     * If an exception occurs during the execution of this method, the given {@code msg} is
     * automatically released when it is of type {@link io.netty.util.ReferenceCounted}.
     *
     * @param sender the sender of the message
     * @param msg    the inbound message
     */
    CompletableFuture<Void> processInbound(Address sender, Object msg);

    /**
     * Processes an inbound event by the pipeline.
     *
     * @param event the inbound event
     */
    CompletableFuture<Void> processInbound(Event event);

    /**
     * Processes an outbound message by the pipeline.
     * <p>
     * If an exception occurs during the execution of this method, the given {@code msg} is
     * automatically released when it is of type {@link io.netty.util.ReferenceCounted}.
     *
     * @param recipient the recipient of the message
     * @param msg       the outbound message
     * @return a completed future if the message was successfully processed, otherwise an
     * exceptionally future
     */
    CompletableFuture<Void> processOutbound(Address recipient, Object msg);
}
