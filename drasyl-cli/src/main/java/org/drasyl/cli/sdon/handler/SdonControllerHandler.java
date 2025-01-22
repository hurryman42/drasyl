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
package org.drasyl.cli.sdon.handler;

import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.drasyl.channel.DrasylChannel;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.sdon.config.Device;
import org.drasyl.cli.sdon.config.Devices;
import org.drasyl.cli.sdon.config.Network;
import org.drasyl.cli.sdon.config.NetworkNode;
import org.drasyl.cli.sdon.config.Policy;
import org.drasyl.cli.sdon.event.SdonMessageReceived;
import org.drasyl.cli.sdon.message.ControllerHello;
import org.drasyl.cli.sdon.message.DeviceCSR;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.cli.sdon.message.SdonMessage;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import org.luaj.vm2.LuaString;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.drasyl.cli.sdon.handler.SdonControllerHandler.State.INITIALIZED;

public class SdonControllerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(SdonControllerHandler.class);
    private final PrintStream out;
    private final Network network;
    private final Devices devices;
    private final java.security.PublicKey publicKey;
    private final PrivateKey privateKey;
    private State state;
    private X509Certificate myCert;
    private String mySubnet;
    private Map<DrasylAddress, String> subControllerSubnets; // is this the best way to keep track of the sub-controllers here?

    SdonControllerHandler(final PrintStream out,
                          final Network network,
                          final Devices devices,
                          final java.security.PublicKey publicKey,
                          final PrivateKey privateKey) {
        this.out = requireNonNull(out);
        this.network = requireNonNull(network);
        this.devices = requireNonNull(devices);
        this.publicKey = requireNonNull(publicKey);
        this.privateKey = requireNonNull(privateKey);
    }

    public SdonControllerHandler(final PrintStream out,
                                 final Network network,
                                 final java.security.PublicKey publicKey,
                                 final PrivateKey privateKey) {
        this(out, network, new Devices(), publicKey, privateKey);
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) {
        if (ctx.channel().isActive()) {
            ensureHandlerInitialized(ctx);
        }
    }

    @Override
    public void channelActive(final ChannelHandlerContext ctx) {
        ensureHandlerInitialized(ctx);
        ctx.fireChannelActive();
    }

    private void ensureHandlerInitialized(final ChannelHandlerContext ctx) {
        if (state == null) {
            state = INITIALIZED;

            out.println("------------------------------------------------------------------------------------------------");
            out.println("Controller listening on address " + ctx.channel().localAddress());
            out.println("------------------------------------------------------------------------------------------------");

            ctx.executor().scheduleAtFixedRate(() -> {
                try {
                    // call callback
                    network.callCallback(devices);

                    // do matchmaking
                    final Set<Device> assignedDevices = new HashSet<>();
                    final Map<LuaString, NetworkNode> nodes = network.getNodes();
                    for (final Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                        final NetworkNode node = entry.getValue();

                        Device bestMatch = null;
                        int minDistance = Integer.MAX_VALUE;
                        for (final Device device : devices.getDevicesCollection()) {
                            if (!assignedDevices.contains(device)) {
                                final int distance = node.getDistance(device);
                                if (distance < minDistance) {
                                    minDistance = distance;
                                    bestMatch = device;
                                }
                            }
                        }

                        if (bestMatch != null) {
                            assignedDevices.add(bestMatch);
                            node.setDevice(bestMatch);
                        }
                    }

                    // disseminate policies
                    for (final Device device : devices.getDevicesCollection()) {
                        NetworkNode node = null;
                        for (final Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                            if (Objects.equals(entry.getValue().device(), device.address())) {
                                node = entry.getValue();
                            }
                        }
                        final Set<Policy> policies;
                        final List<String> certificates;
                        if (node != null) {
                            policies = node.createPolicies();
                            certificates = node.loadCertificates("chain.crt");

                            final String myCertString = certificates.getLast();
                            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            myCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(myCertString.getBytes()));

                            final String myCertSubjectString = myCert.getSubjectX500Principal().toString(); // TODO: test this!!!
                            int startIndex = myCertSubjectString.indexOf("CN=");
                            if (startIndex != -1) {
                                startIndex += 3;
                                int endIndex = myCertSubjectString.indexOf(",", startIndex);
                                if (endIndex == -1) {
                                    endIndex = myCertSubjectString.length();
                                }
                                mySubnet = myCertSubjectString.substring(startIndex, endIndex).trim();

                                final String[] mySubnetSplit = mySubnet.split("/");
                                final InetAddress address = InetAddress.getByName(mySubnetSplit[0]);
                                final short netmask = Short.parseShort(mySubnetSplit[1]);

                                // the smallerSubnet String is always created but only when a devicePolicy with this subnet is created, it is added to subControllerSubnets
                                final String smallerSubnet = address.toString() + "/" + (netmask + 8); // + 8 probably not the best always
                                Set<Policy> devicePolicies = device.createPolicies(smallerSubnet);
                                if (!devicePolicies.isEmpty()) {
                                    subControllerSubnets.put(device.address(), smallerSubnet);
                                    policies.addAll(devicePolicies);
                                }
                            }
                            else {
                                throw new IOException("Error reading the subnet out of the certificate!");
                            }
                        }
                        else {
                            policies = Set.of();
                            certificates = List.of();
                        }

                        final ControllerHello controllerHello = new ControllerHello(policies, certificates);
                        LOG.debug("Send {} to {}.", controllerHello.toString().replace("\n", ""), device.address());
                        final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(device.address());
                        if (channel != null) {
                            channel.writeAndFlush(controllerHello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                        }
                        else {
                            LOG.warn("No channel to device {} found.", device.address());
                        }
                    }
                }
                catch (final Exception e) {
                    ctx.fireExceptionCaught(e);
                }
            }, 1_000, 5_000, MILLISECONDS);
        }
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx,
                                   final Object evt) throws IOException, CertificateException, OperatorCreationException {
        if (evt instanceof SdonMessageReceived) {
            final DrasylAddress sender = ((SdonMessageReceived) evt).address();
            final SdonMessage msg = ((SdonMessageReceived) evt).msg();
            LOG.trace("Received from `{}`: {}`", sender, msg);

            if (msg instanceof DeviceHello) {
                final DeviceHello deviceHello = (DeviceHello) msg;

                // add devices
                final Device device = devices.getOrCreateDevice(sender);
                device.setFacts(deviceHello.facts());
                device.setPolicies(deviceHello.policies());

                final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(sender);
                if (device.isOffline()) {
                    channel.closeFuture().addListener((ChannelFutureListener) future -> {
                        device.setOffline();
                        out.println("Device " + sender + " deregistered.");
                    });

                    device.setOnline();
                    out.println("Device " + sender + " registered.");

                    final ControllerHello controllerHello = new ControllerHello();
                    LOG.debug("Send {} to {}.", controllerHello, sender);
                    channel.writeAndFlush(controllerHello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                }
            }
            else if (msg instanceof DeviceCSR) {
                final DeviceCSR deviceCSR = (DeviceCSR) msg;
                final String csrString = deviceCSR.csr();

                final PEMParser pemParserCSR = new PEMParser(new StringReader(csrString));
                final PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParserCSR.readObject();
                pemParserCSR.close();
                final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                // get public key out of the CSR
                final SubjectPublicKeyInfo csrPublicKeyInfo = csr.getSubjectPublicKeyInfo();
                final PublicKey csrPublicKey = converter.getPublicKey(csrPublicKeyInfo);

                // get subject out of the CSR & check if it is right
                final X500Name csrSubject = csr.getSubject();
                System.out.println("Subject of the CSR is: " + csrSubject);
                final String csrSubjectString = csrSubject.toString();
                int startIndex = csrSubjectString.indexOf("CN=");
                if (startIndex != -1) {
                    startIndex += 3;
                    int endIndex = csrSubjectString.indexOf(",", startIndex);
                    if (endIndex == -1) {
                        endIndex = csrSubjectString.length();
                    }
                    final String subnetAddress = csrSubjectString.substring(startIndex, endIndex).trim();
                    System.out.println(subnetAddress);
                    if (!subControllerSubnets.get(sender).equals(subnetAddress)) {
                        throw new CertificateException("Wrong subnet address in CSR!");
                    }
                }

                // create infos for the new X509 certificate
                final BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
                final Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
                final Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

                // create certificate builder (subject taken from CSR)
                final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(myCert, serialNumber, notBefore, notAfter, csrSubject, csrPublicKey);
                // create a content signer
                final ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
                // build the certificate
                final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

                final ControllerHello response = new ControllerHello();
                // TODO: send the certificate back (as a certificate in the ControllerHello (somehow tell the Device that there is an special extra certificate in this message))
                final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(sender);

                //final SdonMessage response = null; // specify actual response

                LOG.debug("Send {} to {}.", response, sender);
                channel.writeAndFlush(response).addListener(FIRE_EXCEPTION_ON_FAILURE);
            }
        }
        else {
            ctx.fireUserEventTriggered(evt);
        }
    }

    enum State {
        INITIALIZED,
    }
}
