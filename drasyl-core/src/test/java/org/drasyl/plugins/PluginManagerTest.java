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
package org.drasyl.plugins;

import org.drasyl.DrasylConfig;
import org.drasyl.DrasylException;
import org.drasyl.pipeline.Pipeline;
import org.drasyl.util.DrasylFunction;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PluginManagerTest {
    @Mock
    private Map<String, DrasylPlugin> plugins;
    @Mock
    private Pipeline pipeline;
    @Mock
    private DrasylConfig config;
    @Mock
    private DrasylFunction<Class<? extends AutoloadablePlugin>, Constructor<?>, Exception> constructorFunction;

    @Test
    void shouldNotLoadAnyPluginOnEmptyList() throws DrasylException {
        PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
        manager.beforeStart();

        verifyNoInteractions(plugins);
    }

    @Test
    void shouldAddPlugin() throws DrasylException {
        PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);

        DrasylPlugin plugin = mock(DrasylPlugin.class);
        when(plugin.name()).thenReturn("PluginName");

        manager.add(plugin);

        verify(plugins).put(plugin.name(), plugin);
        verify(plugin).onBeforeStart();
    }

    @Test
    void shouldThrowExceptionOnDuplicatePlugin() {
        PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
        DrasylPlugin plugin = mock(DrasylPlugin.class);
        when(plugin.name()).thenReturn("PluginName");
        when(plugins.containsKey(plugin.name())).thenReturn(true);

        assertThrows(DrasylException.class, () -> manager.add(plugin));
    }

    @Test
    void shouldRemovePluginsOnShutdown() {
        DrasylPlugin plugin = mock(DrasylPlugin.class);
        when(plugins.values()).thenReturn(List.of(plugin));

        PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);

        manager.afterShutdown();

        verify(plugin).onAfterShutdown();
        verify(plugins).clear();
    }

    @Test
    void shouldLoadAllPluginsThatAreDefinedInTheDrasylConfig() throws DrasylException {
        PluginEnvironment env = mock(PluginEnvironment.class);

        when(config.getPluginEnvironments()).thenReturn(List.of(env));
        doReturn(PluginManagerTest.TestPlugin.class).when(env).getClazz();

        constructorFunction = clazz -> clazz.getConstructor(Pipeline.class, DrasylConfig.class, PluginEnvironment.class);

        PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
        manager.beforeStart();

        verify(plugins).put(isA(String.class), isA(TestPlugin.class));
    }

    @Nested
    class ExceptionRethrowing {
        @Test
        void rethrowNoSuchMethodException() throws Exception {
            PluginEnvironment env = mock(PluginEnvironment.class);
            doReturn(PluginManagerTest.TestPlugin.class).when(env).getClazz();
            when(constructorFunction.apply(any())).thenThrow(NoSuchMethodException.class);

            PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
            assertThrows(DrasylException.class, () -> manager.loadPlugin(env));
        }

        @Test
        void rethrowIllegalAccessException() throws Exception {
            PluginEnvironment env = mock(PluginEnvironment.class);
            doReturn(PluginManagerTest.TestPlugin.class).when(env).getClazz();
            when(constructorFunction.apply(any())).thenThrow(IllegalAccessException.class);

            PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
            assertThrows(DrasylException.class, () -> manager.loadPlugin(env));
        }

        @Test
        void rethrowInstantiationException() throws Exception {
            PluginEnvironment env = mock(PluginEnvironment.class);
            doReturn(PluginManagerTest.TestPlugin.class).when(env).getClazz();
            when(constructorFunction.apply(any())).thenThrow(InstantiationException.class);

            PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
            assertThrows(DrasylException.class, () -> manager.loadPlugin(env));
        }

        @Test
        void rethrowExceptionn() throws Exception {
            PluginEnvironment env = mock(PluginEnvironment.class);
            doReturn(PluginManagerTest.TestPlugin.class).when(env).getClazz();
            when(constructorFunction.apply(any())).thenThrow(Exception.class);

            PluginManager manager = new PluginManager(pipeline, config, plugins, constructorFunction);
            assertThrows(DrasylException.class, () -> manager.loadPlugin(env));
        }
    }

    @Nested
    class OnEvent {
        @Test
        void shouldEmitEvenOnBeforeStart() throws DrasylException {
            PluginManager manager = new PluginManager(pipeline, config, new HashMap<>(), constructorFunction);

            DrasylPlugin plugin = mock(DrasylPlugin.class);
            when(plugin.name()).thenReturn("PluginName");

            manager.add(plugin);
            manager.beforeStart();

            verify(plugin).onBeforeStart();
        }

        @Test
        void shouldEmitEvenOnBeforeShutdown() throws DrasylException {
            PluginManager manager = new PluginManager(pipeline, config, new HashMap<>(), constructorFunction);

            DrasylPlugin plugin = mock(DrasylPlugin.class);
            when(plugin.name()).thenReturn("PluginName");

            manager.add(plugin);
            manager.beforeShutdown();

            verify(plugin).onBeforeShutdown();
        }

        @Test
        void shouldEmitEvenOnAfterStart() throws DrasylException {
            PluginManager manager = new PluginManager(pipeline, config, new HashMap<>(), constructorFunction);

            DrasylPlugin plugin = mock(DrasylPlugin.class);
            when(plugin.name()).thenReturn("PluginName");

            manager.add(plugin);
            manager.afterStart();

            verify(plugin).onAfterStart();
        }

        @Test
        void shouldEmitEvenOnAfterStop() throws DrasylException {
            PluginManager manager = new PluginManager(pipeline, config, new HashMap<>(), constructorFunction);

            DrasylPlugin plugin = mock(DrasylPlugin.class);
            when(plugin.name()).thenReturn("PluginName");

            manager.add(plugin);
            manager.afterShutdown();

            verify(plugin).onAfterShutdown();
        }
    }

    public static class TestPlugin extends AutoloadablePlugin {
        public TestPlugin(Pipeline pipeline,
                          DrasylConfig config,
                          PluginEnvironment environment) {
            super(pipeline, config, environment);
        }

        @Override
        public String name() {
            return "PluginManagerTest.TestPlugin";
        }

        @Override
        public void onAfterStart() {
            // Do nothing
        }

        @Override
        public void onAfterShutdown() {
            // Do nothing
        }

        @Override
        public void onBeforeStart() {
            // Do nothing
        }

        @Override
        public void onBeforeShutdown() {
            // Do nothing
        }
    }
}