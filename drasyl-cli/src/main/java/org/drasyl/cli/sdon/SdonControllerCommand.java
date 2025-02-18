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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.drasyl.cli.ChannelOptions;
import org.drasyl.cli.ChannelOptionsDefaultProvider;
import org.drasyl.cli.sdon.channel.SdonControllerChannelInitializer;
import org.drasyl.cli.sdon.channel.SdonControllerChildChannelInitializer;
import org.drasyl.cli.sdon.config.NetworkConfig;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.Worm;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

@Command(
        name = "controller",
        header = "Controls the overlay network.",
        defaultValueProvider = ChannelOptionsDefaultProvider.class
)
public class SdonControllerCommand extends ChannelOptions {
    private static final Logger LOG = LoggerFactory.getLogger(SdonControllerCommand.class);
    @Option(
            names = {"-c", "--config"},
            description = "Loads the node configuration from specified file.",
            paramLabel = "<file>",
            defaultValue = "network-conf.lua"
    )
    private File configFile;

    @Option(
            names = {"--pub-key"},
            description = "Loads the controller's public key from specified file.",
            paramLabel = "<file>",
            defaultValue = "controller-pub.pem"
    )
    private File pubKeyFile;

    @Option(
            names = {"--priv-key"},
            description = "Loads the controller's private key from specified file.",
            paramLabel = "<file>",
            defaultValue = "controller-priv.key"
    )
    private File privKeyFile;

    @Option(
            names = {"--cert-chain"},
            description = "Loads the controller's certificate from specified file.",
            paramLabel = "<file>",
            defaultValue = "chain.crt"
    )
    private File certFile;

    private NetworkConfig config;
    private java.security.PublicKey publicKey;
    private PrivateKey privateKey;
    private List<String> certificates;

    SdonControllerCommand(final PrintStream out,
                          final PrintStream err,
                          final Level logLevel,
                          final File identityFile,
                          final InetSocketAddress bindAddress,
                          final int onlineTimeoutMillis,
                          final int networkId,
                          final Map<IdentityPublicKey, InetSocketAddress> superPeers,
                          final File configFile,
                          final File pubKeyFile,
                          final File privKeyFile,
                          final File certFile) {
        super(out, err, logLevel, identityFile, bindAddress, onlineTimeoutMillis, networkId, superPeers);
        this.configFile = requireNonNull(configFile);
        this.pubKeyFile = requireNonNull(pubKeyFile);
        this.privKeyFile = requireNonNull(privKeyFile);
        this.certFile = requireNonNull(certFile);
    }

    @SuppressWarnings("unused")
    public SdonControllerCommand() {
    }

    @Override
    public Integer call() {
        try {
            config = NetworkConfig.parseFile(configFile);

            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            final PEMParser pemParserPublicKey = new PEMParser(new FileReader(pubKeyFile));
            final SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) pemParserPublicKey.readObject();
            pemParserPublicKey.close();
            publicKey = converter.getPublicKey(publicKeyInfo);

            final PEMParser pemParserPrivateKey = new PEMParser(new FileReader(privKeyFile));
            final PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParserPrivateKey.readObject();
            pemParserPrivateKey.close();
            privateKey = converter.getPrivateKey(privateKeyInfo);

            certificates = new ArrayList<>();
            final String certsString = Files.readString(certFile.toPath());
            final String[] certs = certsString.split("-----END CERTIFICATE-----");
            for (int i = 0; i < (certs.length - 1); i++) {
                String cert = certs[i] + "-----END CERTIFICATE-----\n";
                if (cert.startsWith("\n")) {
                    cert = cert.substring(1);
                }
                certificates.add(cert);
            }

            return super.call();
        }
        catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(final Worm<Integer> exitCode) {
        return new SdonControllerChannelInitializer(onlineTimeoutMillis, out, err, exitCode, config.network(), publicKey, privateKey, certificates);
    }

    @Override
    protected ChannelHandler getChildChannelInitializer(final Worm<Integer> exitCode) {
        return new SdonControllerChildChannelInitializer(out, err, exitCode, config, publicKey, privateKey, certificates);
    }

    @Override
    protected Logger log() {
        return LOG;
    }
}
