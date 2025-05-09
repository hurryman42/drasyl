/*
 * Copyright (c) 2020-2024 Heiko Bornholdt and Kevin Röbert
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
package org.drasyl.cli.sdon.message;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.drasyl.cli.sdon.config.Policy;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Message sent from the controller to all devices.
 */
public class ControllerHello implements SdonMessage {
    // policies later as certificate extensions?
    private final Set<Policy> policies;
    private final List<String> certificates;

    @JsonCreator
    public ControllerHello(@JsonProperty("policies") final Set<Policy> policies,
                           @JsonProperty("certificates") final List<String> certificates) {
        this.policies = requireNonNull(policies);
        this.certificates = requireNonNull(certificates);
    }

    public ControllerHello() {
        this(Set.of(), List.of());
    }

    @JsonGetter
    public Set<Policy> policies() {
        return policies;
    }

    @JsonGetter
    public List<String> certificates() {
        return certificates;
    }

    @Override
    public String toString() {
        return "ControllerHello{" +
                "policies='" + policies + '\'' +
                ", certificates='" + certificates + '\'' +
                '}';
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ControllerHello that = (ControllerHello) o;
        return (Objects.equals(policies, that.policies) && Objects.equals(certificates, that.certificates));
    }

    @Override
    public int hashCode() {
        return Objects.hash(policies, certificates);
    }
}
