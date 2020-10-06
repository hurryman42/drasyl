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

package org.drasyl.monitoring;

import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.influx.InfluxConfig;
import io.micrometer.influx.InfluxMeterRegistry;
import org.drasyl.DrasylConfig;
import org.drasyl.DrasylNodeComponent;
import org.drasyl.event.Event;
import org.drasyl.identity.CompressedPublicKey;
import org.drasyl.peer.PeersManager;
import org.drasyl.pipeline.HandlerContext;
import org.drasyl.pipeline.Pipeline;
import org.drasyl.pipeline.SimpleDuplexHandler;
import org.drasyl.util.NetworkUtil;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static java.util.Optional.ofNullable;

/**
 * Monitors various states or events in the drasyl Node.
 */
public class Monitoring implements DrasylNodeComponent {
    private static final Logger LOG = LoggerFactory.getLogger(Monitoring.class);
    static final String MONITORING_HANDLER = "MONITORING_HANDLER";
    private final PeersManager peersManager;
    private final CompressedPublicKey publicKey;
    private final Pipeline pipeline;
    private final AtomicBoolean opened;
    private final Supplier<MeterRegistry> registrySupplier;
    private MeterRegistry registry;

    public Monitoring(final DrasylConfig config,
                      final PeersManager peersManager,
                      final CompressedPublicKey publicKey,
                      final Pipeline pipeline) {
        this(
                peersManager,
                publicKey,
                pipeline,
                () -> new InfluxMeterRegistry(new InfluxConfig() {
                    @Override
                    public @NotNull String uri() {
                        return config.getMonitoringInfluxUri().toString();
                    }

                    @Override
                    public String userName() {
                        return config.getMonitoringInfluxUser();
                    }

                    @Override
                    public String password() {
                        return config.getMonitoringInfluxPassword();
                    }

                    @Override
                    public @NotNull String db() {
                        return config.getMonitoringInfluxDatabase();
                    }

                    @Override
                    public boolean autoCreateDb() {
                        return false;
                    }

                    @Override
                    public @NotNull Duration step() {
                        return config.getMonitoringInfluxReportingFrequency();
                    }

                    @Override
                    public String get(final @NotNull String key) {
                        return null;
                    }
                }, Clock.SYSTEM), new AtomicBoolean(),
                null
        );
    }

    Monitoring(final PeersManager peersManager,
               final CompressedPublicKey publicKey,
               final Pipeline pipeline,
               final Supplier<MeterRegistry> registrySupplier,
               final AtomicBoolean opened,
               final MeterRegistry registry) {
        this.peersManager = peersManager;
        this.publicKey = publicKey;
        this.pipeline = pipeline;
        this.opened = opened;
        this.registrySupplier = registrySupplier;
        this.registry = registry;
    }

    @Override
    public void open() {
        if (opened.compareAndSet(false, true)) {
            LOG.debug("Start Monitoring...");
            registry = registrySupplier.get();

            // add common tags
            registry.config().commonTags(
                    "public_key", publicKey.toString(),
                    "host", ofNullable(NetworkUtil.getLocalHostName()).orElse("")
            );

            // monitor PeersManager
            Gauge.builder("peersManager.peers", peersManager, pm -> pm.getPeers().size()).register(registry);
            Gauge.builder("peersManager.superPeer", peersManager, pm -> pm.getSuperPeerKey() != null ? 1 : 0).register(registry);
            Gauge.builder("peersManager.children", peersManager, pm -> pm.getChildrenKeys().size()).register(registry);

            // monitor Pipeline
            pipeline.addFirst(MONITORING_HANDLER, new SimpleDuplexHandler<Object, Event, Object>() {
                private final Map<String, Counter> counters = new HashMap<>();

                @Override
                protected void matchedEventTriggered(final HandlerContext ctx,
                                                     final Event event,
                                                     final CompletableFuture<Void> future) {
                    ctx.scheduler().scheduleDirect(() -> incrementObjectTypeCounter("pipeline.events", event));
                    ctx.fireEventTriggered(event, future);
                }

                @Override
                protected void matchedRead(final HandlerContext ctx,
                                           final CompressedPublicKey sender,
                                           final Object msg,
                                           final CompletableFuture<Void> future) {
                    ctx.scheduler().scheduleDirect(() -> incrementObjectTypeCounter("pipeline.inbound_messages", msg));
                    ctx.fireRead(sender, msg, future);
                }

                @Override
                protected void matchedWrite(final HandlerContext ctx,
                                            final CompressedPublicKey recipient,
                                            final Object msg,
                                            final CompletableFuture<Void> future) {
                    ctx.scheduler().scheduleDirect(() -> incrementObjectTypeCounter("pipeline.outbound_messages", msg));
                    ctx.write(recipient, msg, future);
                }

                private void incrementObjectTypeCounter(final String metric, final Object o) {
                    final Counter counter = counters.computeIfAbsent(o.getClass().getSimpleName(), clazz -> Counter.builder(metric).tag("clazz", clazz).register(registry));
                    counter.increment();
                }
            });
            LOG.debug("Monitoring started.");
        }
    }

    @Override
    public void close() {
        if (opened.compareAndSet(true, false)) {
            LOG.debug("Stop Monitoring...");
            pipeline.remove(MONITORING_HANDLER);
            registry.close();
            registry = null;
            LOG.debug("Monitoring stopped.");
        }
    }
}