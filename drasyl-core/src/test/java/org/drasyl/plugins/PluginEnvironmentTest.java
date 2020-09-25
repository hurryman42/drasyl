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

import com.typesafe.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class PluginEnvironmentTest {
    @Mock
    private Config options;
    private final Class<? extends AutoloadablePlugin> clazz = AutoloadablePlugin.class;

    @Test
    void shouldReturnCorrectOptions() {
        PluginEnvironment env = new PluginEnvironment(options, clazz);

        assertEquals(options, env.getOptions().getConfig());
    }

    @Test
    void shouldReturnCorrectClass() {
        PluginEnvironment env = new PluginEnvironment(options, clazz);

        assertEquals(clazz, env.getClazz());
    }
}