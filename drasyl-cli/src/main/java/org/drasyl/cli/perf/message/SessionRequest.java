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
package org.drasyl.cli.perf.message;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Sent from the {@link PerfClientNode} to the {@link PerfServerNode} to request a new session.
 */
public class SessionRequest implements PerfMessage {
    private final int time;
    private final int mps;
    private final int size;
    private final boolean reverse;

    /**
     * @throws IllegalArgumentException if {@code testDuration}, {@code totalMessages} or {@code
     *                                  messageSize} is less than 1
     */
    @JsonCreator
    public SessionRequest(@JsonProperty("time") final int time,
                          @JsonProperty("mps") final int mps,
                          @JsonProperty("size") final int size,
                          @JsonProperty("reverse") final boolean reverse) {
        this.time = time;
        if (time < 1) {
            throw new IllegalArgumentException("time must be greater than 0");
        }
        this.mps = mps;
        if (mps < 1) {
            throw new IllegalArgumentException("mps must be greater than 0");
        }
        this.size = size;
        if (size < 1) {
            throw new IllegalArgumentException("size must be greater than 0");
        }
        this.reverse = reverse;
    }

    public int getMps() {
        return mps;
    }

    public int getTime() {
        return time;
    }

    public int getSize() {
        return size;
    }

    public boolean isReverse() {
        return reverse;
    }

    @Override
    public String toString() {
        return "{" +
                "time=" + time +
                ", mps=" + mps +
                ", size=" + size +
                ", reverse=" + reverse +
                '}';
    }
}