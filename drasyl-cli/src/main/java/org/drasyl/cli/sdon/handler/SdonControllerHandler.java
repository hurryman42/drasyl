/*
 * Copyright (c) 2020-2025 Heiko Bornholdt and Kevin Röbert
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
import org.drasyl.cli.sdon.config.ControlledPolicy;
import org.drasyl.cli.sdon.config.Device;
import org.drasyl.cli.sdon.config.Devices;
import org.drasyl.cli.sdon.config.Network;
import org.drasyl.cli.sdon.config.NetworkNode;
import org.drasyl.cli.sdon.config.Policy;
import org.drasyl.cli.sdon.event.SdonMessageReceived;
import org.drasyl.cli.sdon.message.ControllerHello;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.cli.sdon.message.SdonMessage;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import org.drasyl.util.network.Subnet;
import org.luaj.vm2.LuaString;

import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
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
    private final List<String> certificates;
    private final X509Certificate myCert;
    private final Subnet mySubnet;
    private State state;
    private final Map<DrasylAddress, String> subControllerSubnets; // is this the best way to keep track of the controller's sub-controllers?
    private int msgCount;

    SdonControllerHandler(final PrintStream out,
                          final Network network,
                          final Devices devices,
                          final java.security.PublicKey publicKey,
                          final PrivateKey privateKey,
                          final List<String> certificates,
                          final X509Certificate myCert,
                          final Subnet mySubnet) {
        this.out = requireNonNull(out);
        this.network = requireNonNull(network);
        this.devices = requireNonNull(devices);
        this.publicKey = requireNonNull(publicKey);
        this.privateKey = requireNonNull(privateKey);
        this.certificates = requireNonNull(certificates);
        this.myCert = requireNonNull(myCert);
        this.mySubnet = requireNonNull(mySubnet);
        this.subControllerSubnets = new HashMap<>();
        this.msgCount = 0;
    }

    public SdonControllerHandler(final PrintStream out,
                                 final Network network,
                                 final java.security.PublicKey publicKey,
                                 final PrivateKey privateKey,
                                 final List<String> certificates,
                                 final X509Certificate myCert,
                                 final Subnet mySubnet) {
        this(out, network, new Devices(), publicKey, privateKey, certificates, myCert, mySubnet);
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
                    network.callCallback(devices); // the callback function removes the to be offloaded devices from the devices variable

                    /* this was the idea to create nodes for all devices in the system at the primary controller and then propagate them through the sub-controllers
                    however, this did not really work and so now each (sub-)controller creates nodes for its devices according to their Lua network configuration
                    // (it cuts out all the sub-controllers & instead adds their devices, which are the actualDevices)
                    Devices allActualDevices = new Devices();
                    Devices allDevices = new Devices();
                    for (Device device : devices.getDevices()) {
                        allDevices.addDevice(device);
                        if (device.isSubController()) {
                            Devices subDevices = device.intendedDevices();
                            for (Device dev : subDevices.getDevices()) {
                                allActualDevices.addDevice(dev);
                                allDevices.addDevice(dev);
                            }
                        }
                        else {
                            allActualDevices.addDevice(device);
                        }
                    }*/

                    // do matchmaking
                    final Set<Device> assignedDevices = new HashSet<>();
                    final Map<LuaString, NetworkNode> nodes = network.getNodes();
                    for (final Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                        final NetworkNode node = entry.getValue();

                        Device bestMatch = null;
                        int minDistance = Integer.MAX_VALUE;
                        for (final Device device : devices.getDevices()) { // allActualDevices.getDevices()
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
                    for (final Device device : devices.getDevices()) { // allDevices.getDevices()
                        NetworkNode node = null;
                        for (final Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                            if (Objects.equals(entry.getValue().device(), device.address())) {
                                node = entry.getValue();
                            }
                        }

                        // create smallerSubnet (is possibly used for SubControllerPolicy) & create devicePolicies
                        final String smallerSubnetString = mySubnet.addressString() + "/" + (mySubnet.netmaskLength() + 8); // FIXME: +8 probably not always the best
                        final Subnet smallerSubnet = new Subnet(smallerSubnetString);

                        final Set<Policy> policies;
                        // important: if there are not enough nodes for all the devices, some devices will get no policies at all
                        if (node != null) {
                            // device got a node --> it is an actualDevice, not a sub-controller
                            policies = node.createPolicies();
                            final Set<Policy> devicePolicies = device.createPolicies(smallerSubnet, ctx.channel().localAddress().toString());
                            if (!devicePolicies.isEmpty()) {
                                subControllerSubnets.put(device.address(), smallerSubnetString);
                                policies.addAll(devicePolicies);
                            }
                        }
                        else {
                            // device got no node --> it is (probably) a sub-controller
                            final Set<Policy> devicePolicies = device.createPolicies(smallerSubnet, ctx.channel().localAddress().toString());
                            if (!devicePolicies.isEmpty()) {
                                subControllerSubnets.put(device.address(), smallerSubnetString);
                                policies = devicePolicies;
                            }
                            else {
                                policies = Set.of();
                            }
                        }

                        final ControllerHello controllerHello = new ControllerHello(policies, certificates);
                        LOG.debug("Send to {}: {}", device.address(), controllerHello.toString().replace("\n", ""));
                        final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(device.address());
                        if (channel != null) {
                            channel.writeAndFlush(controllerHello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                            msgCount++;
                        }
                        else {
                            LOG.warn("No channel to device {} found.", device.address());
                        }
                    }
                    LOG.debug("{}", msgCount);
                    msgCount = 0;
                }
                catch (final Exception e) {
                    ctx.fireExceptionCaught(e);
                }
            }, 1_000, 5_000, MILLISECONDS);
        }
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx, final Object evt) throws IOException, CertificateException, OperatorCreationException {
        if (evt instanceof SdonMessageReceived) {
            final DrasylAddress sender = ((SdonMessageReceived) evt).address();
            final SdonMessage msg = ((SdonMessageReceived) evt).msg();
            //LOG.trace("Received from {}: {}", sender, msg);
            LOG.debug("Received from {}: {}`", sender, msg.toString().replace("\n", ""));
            msgCount++;

            if (msg instanceof DeviceHello) {
                final DeviceHello deviceHello = (DeviceHello) msg;
                final Device device = devices.getOrCreateDevice(sender);

                if (deviceHello.csr().isEmpty()) { // add device, set policies & facts
                    device.setFacts(deviceHello.facts());
                    device.setPolicies(deviceHello.policies());

                    // a sub-controller that wants to be a normal device again sends a DeviceHello with no feedbackPolicies
                    if (device.isSubController() && deviceHello.policies().isEmpty()) {
                        device.setNotSubController();
                        device.removeAllActualDevices();
                        device.removeAllIntendedDevices();
                    }

                    final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(sender);
                    if (device.isOffline()) {
                        channel.closeFuture().addListener((ChannelFutureListener) future -> {
                            device.setOffline();
                            out.println("Device " + sender + " deregistered.");
                            devices.removeDevice(device);
                        });

                        device.setOnline();
                        out.println("Device " + sender + " registered.");

                        final ControllerHello controllerHello = new ControllerHello(Set.of(), certificates);
                        LOG.debug("Send to {}: {}.", sender, controllerHello.toString().replace("\n", ""));
                        channel.writeAndFlush(controllerHello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                    }
                }
                else { // sign CSR, send new certificate to the controller & send controlledPolicy to all offloaded devices as a goodbye from the controller
                    final String csrString = deviceHello.csr();

                    final PEMParser pemParserCSR = new PEMParser(new StringReader(csrString));
                    final PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pemParserCSR.readObject();
                    pemParserCSR.close();
                    final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

                    // get public key out of the CSR
                    final SubjectPublicKeyInfo csrPublicKeyInfo = csr.getSubjectPublicKeyInfo();
                    final PublicKey csrPublicKey = converter.getPublicKey(csrPublicKeyInfo);

                    // get subject out of the CSR & check if it is right
                    final X500Name csrSubject = csr.getSubject();
                    out.println("------------------------------------------------------------------------------------------------");
                    out.println("Subject of the CSR is: " + csrSubject);
                    out.println("------------------------------------------------------------------------------------------------");
                    final String csrSubjectString = csrSubject.toString();
                    int startIndex = csrSubjectString.indexOf("CN=");
                    if (startIndex != -1) {
                        startIndex += 3;
                        int endIndex = csrSubjectString.indexOf(",", startIndex);
                        if (endIndex == -1) {
                            endIndex = csrSubjectString.length();
                        }
                        final String subnetAddress = csrSubjectString.substring(startIndex, endIndex).trim();
                        //out.println(subnetAddress); // DEBUG
                        if (!subControllerSubnets.get(sender).equals(subnetAddress)) {
                            throw new CertificateException("Wrong subnet address in CSR!");
                        }
                    }

                    // create infos for the new X509 certificate
                    final BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
                    final Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24); // yesterday
                    final Date notAfter = new Date(notBefore.getTime() + 1000L * 60 * 60 * 24 * 365); // a year after yesterday

                    // create certificate (subject taken from CSR)
                    final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(myCert, serialNumber, notBefore, notAfter, csrSubject, csrPublicKey);
                    final ContentSigner signer = new JcaContentSignerBuilder("Ed25519").build(privateKey);
                    final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

                    //final List<String> certificates = loadCertificates("chain.crt"); // the loading of the certificates is now done in the SdonControllerCommand
                    final List<String> certificatesWithNew = new ArrayList<>();
                    certificatesWithNew.add(convertCertToPem(certificate)); // important: the new certificate has to be added at the beginning of the cert-list (the cacert is always the last)
                    certificatesWithNew.addAll(certificates);

                    final String smallerSubnetString = mySubnet.addressString() + "/" + (mySubnet.netmaskLength() + 8); // FIXME: +8 probably not always the best
                    final Subnet smallerSubnet = new Subnet(smallerSubnetString);
                    final Set<Policy> devicePolicies = device.createPolicies(smallerSubnet, ctx.channel().localAddress().toString());
                    final ControllerHello response = new ControllerHello(devicePolicies, certificatesWithNew);

                    final DrasylChannel subControllerChannel = ((DrasylServerChannel) ctx.channel()).getChannels().get(sender);
                    LOG.debug("Send to {}: {}.", sender, response.toString().replace("\n", ""));
                    subControllerChannel.writeAndFlush(response).addListener(FIRE_EXCEPTION_ON_FAILURE);

                    // send goodbye message to all the offloaded devices
                    final ControllerHello goodbyeMsg = new ControllerHello(Set.of(new ControlledPolicy(sender)), certificates);
                    final Collection<Device> devs = device.intendedDevices().getDevices();
                    for (Device dev : devs) {
                        final DrasylChannel goodbyeChannel = ((DrasylServerChannel) ctx.channel()).getChannels().get(dev.address());
                        LOG.debug("Send to {}: {}.", dev.address(), goodbyeMsg.toString().replace("\n", ""));
                        goodbyeChannel.writeAndFlush(goodbyeMsg).addListener(FIRE_EXCEPTION_ON_FAILURE);
                        devices.removeDevice(dev);
                    }
                }
            }
        }
        else {
            ctx.fireUserEventTriggered(evt);
        }
    }

    /**
     * Reads the certificate file, splits the certificate chain in it into the single certificates and returns them as a list of Strings.
     * //@param certFilePath the file path of the certificate(chain) to read
     * //@return String-List of the extracted certificates
     * //@throws IOException if an IO error occurs.
    public List<String> loadCertificates(String certFilePath) throws IOException {
        final List<String> certificates = new ArrayList<>();
        final String certsString = Files.readString(Path.of(certFilePath));
        final String[] certs = certsString.split("-----END CERTIFICATE-----");
        for (int i = 0; i < (certs.length - 1); i++) {
            String cert = certs[i] + "-----END CERTIFICATE-----\n";
            if (cert.startsWith("\n")) {
                cert = cert.substring(1);
            }
            certificates.add(cert);
        }
        return certificates;
    }*/

    private static String convertCertToPem(final X509Certificate certificate) throws CertificateEncodingException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8));
        final byte[] cert = certificate.getEncoded();
        return "-----BEGIN CERTIFICATE-----" + "\n" + encoder.encodeToString(cert) + "\n" + "-----END CERTIFICATE-----";
    }

    enum State {
        INITIALIZED,
    }
}
