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
package org.drasyl.cli.sdon;

import ch.qos.logback.classic.Level;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.DatagramChannel;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.ChannelOptions;
import org.drasyl.cli.ChannelOptionsDefaultProvider;
import org.drasyl.cli.sdon.channel.SdonDeviceChannelInitializer;
import org.drasyl.cli.sdon.channel.SdonDeviceChildChannelInitializer;
import org.drasyl.cli.sdon.handler.UdpServerToTunHandler;
import org.drasyl.handler.remote.UdpServerChannelInitializer;
import org.drasyl.handler.remote.UdpServerToDrasylHandler;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.util.Map;

import static java.util.Objects.requireNonNull;

@Command(
        name = "device",
        header = "Provides local device resources to a controller to create an overlay network.",
        defaultValueProvider = ChannelOptionsDefaultProvider.class
)
public class SdonDeviceCommand extends ChannelOptions {
    private static final Logger LOG = LoggerFactory.getLogger(SdonDeviceCommand.class);
    @Option(
            names = {"-c", "--controller"},
            description = "Controller to register with.",
            paramLabel = "<public-key>",
            required = true
    )
    private IdentityPublicKey controller;
    @Option(
            names = {"--pub-key"},
            description = "Loads the controllers public key from specified file.",
            paramLabel = "<file>",
            defaultValue = "controller-pub.pem"
    )
    private File pubKeyFile;
    @Option(
            names = {"--priv-key"},
            description = "Loads the controllers private key from specified file.",
            paramLabel = "<file>",
            defaultValue = "controller-priv.key"
    )
    private File privKeyFile;
    @Option(
            names = {"--tag"},
            description = "Associate device with given tags, used by controller to assign specific tasks."
    )
    private String[] tags = new String[0];

    private java.security.PublicKey publicKey;
    private PrivateKey privateKey;

    public SdonDeviceCommand(final PrintStream out,
                             final PrintStream err,
                             final Level logLevel,
                             final File identityFile,
                             final InetSocketAddress bindAddress,
                             final int onlineTimeoutMillis,
                             final int networkId,
                             final Map<IdentityPublicKey, InetSocketAddress> superPeers,
                             final IdentityPublicKey controller,
                             final File pubKeyFile,
                             final File privKeyFile,
                             final String[] tags) {
        super(out, err, logLevel, identityFile, bindAddress, onlineTimeoutMillis, networkId, superPeers);
        this.controller = requireNonNull(controller);
        this.pubKeyFile = requireNonNull(pubKeyFile);
        this.privKeyFile = requireNonNull(privKeyFile);
        this.tags = requireNonNull(tags);

        try {
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            final PEMParser pemParserPublicKey = new PEMParser(new FileReader(this.pubKeyFile));
            final SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParserPublicKey.readObject();
            pemParserPublicKey.close();
            publicKey = converter.getPublicKey(publicKeyInfo);

            final PEMParser pemParserPrivateKey = new PEMParser(new FileReader(this.privKeyFile));
            final PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParserPrivateKey.readObject();
            pemParserPrivateKey.close();
            privateKey = converter.getPrivateKey(privateKeyInfo);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unused")
    public SdonDeviceCommand() {
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(final Worm<Integer> exitCode) {
        return new SdonDeviceChannelInitializer(onlineTimeoutMillis, out, err, exitCode, controller, publicKey, privateKey, tags);
    }

    @Override
    protected ChannelHandler getChildChannelInitializer(final Worm<Integer> exitCode) {
        return new SdonDeviceChildChannelInitializer(out, err, exitCode, controller);
    }

    @Override
    protected ChannelHandler getUdpChannelInitializer(final DrasylServerChannel parent) {
        return new UdpServerChannelInitializer(parent) {
            @Override
            protected void initChannel(final DatagramChannel ch) {
                super.initChannel(ch);

                final ChannelPipeline p = ch.pipeline();

                ch.pipeline().addBefore(p.context(UdpServerToDrasylHandler.class).name(), null, new UdpServerToTunHandler(parent));
            }
        };
    }

    @Override
    protected Logger log() {
        return LOG;
    }
}

