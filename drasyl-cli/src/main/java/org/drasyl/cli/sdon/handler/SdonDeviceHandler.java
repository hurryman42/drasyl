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

import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.sdon.config.ControlledPolicy;
import org.drasyl.cli.sdon.config.Device;
import org.drasyl.cli.sdon.config.Devices;
import org.drasyl.cli.sdon.config.SubControllerPolicy;
import org.drasyl.cli.sdon.config.Policy;
import org.drasyl.cli.sdon.config.TunPolicy;
import org.drasyl.cli.sdon.event.SdonMessageReceived;
import org.drasyl.cli.sdon.message.ControllerHello;
import org.drasyl.cli.sdon.message.DeviceCSR;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.cli.sdon.message.SdonMessage;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.drasyl.cli.sdon.handler.SdonDeviceHandler.State.INITIALIZED;
import static org.drasyl.cli.sdon.handler.SdonDeviceHandler.State.JOINED;
import static org.drasyl.cli.sdon.handler.SdonDeviceHandler.State.JOINING;
import static org.drasyl.util.RandomUtil.randomInt;

public class SdonDeviceHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(SdonDeviceHandler.class);
    private static final int DEVICE_HELLO_INTERVAL = 5_000; // every 5 seconds
    private final PrintStream out;
    private final IdentityPublicKey controller;
    public final PublicKey publicKey;
    public final PrivateKey privateKey;
    private X509Certificate certificate;
    private final Map<String, Object> facts;
    State state;
    public final Set<Policy> policies = new HashSet<>();

    public SdonDeviceHandler(final PrintStream out,
                             final IdentityPublicKey controller,
                             final java.security.PublicKey publicKey,
                             final PrivateKey privateKey,
                             final Map<String, Object> facts) {
        this.out = requireNonNull(out);
        this.controller = requireNonNull(controller);
        this.publicKey = requireNonNull(publicKey);
        this.privateKey = requireNonNull(privateKey);
        this.facts = requireNonNull(facts);
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

            out.println("----------------------------------------------------------------------------------------------");
            out.println("Device listening on address " + ctx.channel().localAddress());
            out.println("----------------------------------------------------------------------------------------------");

            out.print("Connecting to controller " + controller + "...");
            ((DrasylServerChannel) ctx.channel()).serve(controller).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    if (state == INITIALIZED) {
                        final Channel channel = future.channel();
                        out.println("Connected!");
                        out.print("Register at controller...");
                        state = JOINING;
                        final DeviceHello hello = new DeviceHello(facts, policies);
                        LOG.debug("Send `{}`", hello);
                        channel.writeAndFlush(hello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                    }
                }
            });

            ctx.executor().scheduleAtFixedRate(() -> ((DrasylServerChannel) ctx.channel()).serve(controller).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    if (state == JOINED) {
                        final Channel channel = future.channel();
                        final DeviceHello hello = new DeviceHello(facts, policies);
                        LOG.debug("Send `{}`", hello);
                        channel.writeAndFlush(hello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                    }
                }
            }), randomInt(0, DEVICE_HELLO_INTERVAL), DEVICE_HELLO_INTERVAL, MILLISECONDS);
        }
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx,
                                   final Object evt) throws Exception {
        if (evt instanceof SdonMessageReceived) {
            final DrasylAddress sender = ((SdonMessageReceived) evt).address();
            final SdonMessage msg = ((SdonMessageReceived) evt).msg();
            LOG.debug("Received from `{}`: {}", sender, msg.toString().replace("\n", ""));

            if (sender.equals(controller) && msg instanceof ControllerHello) {
                final ControllerHello controllerHello = (ControllerHello) msg;
                final List<String> certificates = controllerHello.certificates();
                //certificates.replaceAll(s -> s.replace("\n", ""));

                if (!certificates.isEmpty() && !controllerHello.policies().isEmpty()) {
                    // load rootCertificate from file & check whether it equals the last certificate in the message
                    final String rootCertFilePath = "cacert.crt"; // TODO: make this more dynamic (command inputs?)
                    final String rootCertString = Files.readString(Path.of(rootCertFilePath));
                    if (!(certificates.get(certificates.size() - 1).equals(rootCertString))) {
                        throw new CertificateException("Not the right root certificate!");
                    }

                    // check validity of the sender's certificates
                    final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    for (int i = 0; i < certificates.size() - 1; i++) {
                        // load current certificate
                        final String certificateString = certificates.get(i);
                        final X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateString.getBytes()));

                        // load next certificate (one up the chain)
                        final String nextCertString = certificates.get(i + 1);
                        final X509Certificate nextCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(nextCertString.getBytes()));

                        // check expiration dates
                        certificate.checkValidity(new Date());
                        nextCert.checkValidity(new Date());

                        // verify current certificate with the public key of the next certificate
                        final PublicKey nextPubKey = nextCert.getPublicKey();
                        certificate.verify(nextPubKey);
                    }

                    // check subnet address
                    final String certString = certificates.get(0);
                    final X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certString.getBytes()));
                    final X500Name subject = new JcaX509CertificateHolder(cert).getSubject();
                    final String subjectString = subject.toString();
                    final String[] subjectInfos = subjectString.split(",");
                    final String subnet = subjectInfos[0].substring(3);
                    out.println("Valid X.509 certificate for subnet " + subnet);
                    final String[] subnetSplit = subnet.split("/");
                    final InetAddress subnetAddress = InetAddress.getByName(subnetSplit[0]);
                    final byte[] subnetAddressBytes = subnetAddress.getAddress();
                    final short subnetNetmask = Short.parseShort(subnetSplit[1]);

                    final Set<Policy> policies = controllerHello.policies();
                    for (Policy policy : policies) {
                        if (policy instanceof TunPolicy) {
                            final TunPolicy tunPolicy = (TunPolicy) policy;
                            final InetAddress ipAddress = tunPolicy.address();
                            final byte[] ipAddressBytes = ipAddress.getAddress();

                            final short netmask = tunPolicy.netmask();

                            final int numBytesToMask = subnetNetmask / 8;
                            final int remainingBits = subnetNetmask % 8;

                            final byte[] mask = new byte[ipAddressBytes.length];
                            for (int i = 0; i < numBytesToMask; i++) {
                                mask[i] = (byte) 0xFF;
                            }
                            if (remainingBits > 0) {
                                mask[numBytesToMask] = (byte) (0xFF << (8 - remainingBits));
                            }

                            final byte[] maskedIp = new byte[ipAddressBytes.length];
                            final byte[] maskedSubnet = new byte[subnetAddressBytes.length];
                            for (int i = 0; i < ipAddressBytes.length; i++) {
                                maskedIp[i] = (byte) (ipAddressBytes[i] & mask[i]);
                                maskedSubnet[i] = (byte) (subnetAddressBytes[i] & mask[i]);
                            }

                            if (!(InetAddress.getByAddress(maskedIp).equals(InetAddress.getByAddress(maskedSubnet)))) {
                                throw new Exception("IP address in policy does not fit in the subnet specified in the controller's certificate!");
                            }
                            else {
                                out.println("Success: IP address in policy fits in the subnet specified in the controller's certificate!");
                            }
                            /*if (!(netmask == subnetNetmask)) {
                                throw new Exception("The netmask of the IP address from the policy is not the same as netmask from the controller's certificate.");
                            }*/
                        }
                        else if (policy instanceof SubControllerPolicy) {
                            final SubControllerPolicy subControllerPolicy = (SubControllerPolicy) policy;
                            final Boolean isSubController = subControllerPolicy.is_sub_controller();
                            final DrasylAddress myAddress = subControllerPolicy.address();

                            /*
                            // check whether I have the certificate already, not via this weird state
                            if (!isSubController) { // start SubController creation process: create and send a DeviceCSR
                                final String csrAsString = createCSR(publicKey, privateKey, subControllerPolicy.subnet());
                                final DeviceCSR subControllerCSR = new DeviceCSR(csrAsString);
                                out.println("Generated DeviceCSR message. Sending to controller now.");

                                // send the CSR message
                                ((DrasylServerChannel) ctx.channel()).serve(subControllerPolicy.controller()).addListener((ChannelFutureListener) future -> {
                                    if (future.isSuccess()) {
                                        final Channel channelToController = future.channel();
                                        channelToController.writeAndFlush(subControllerCSR).addListener(FIRE_EXCEPTION_ON_FAILURE);
                                    }
                                    else {
                                        throw (Exception) future.cause();
                                    }
                                });
                            }*/
                            // the device is a sub-controller --> it receives SubControllerPolicies & sends ControlledPolicies to its devices
                            final Set<DrasylAddress> myDeviceAddresses = subControllerPolicy.devices();
                            final Devices myDevices = new Devices();

                            // maybe individual policy type created by that sub-controller and only send by it (metaprogramming)
                            final ControlledPolicy controlledPolicy = new ControlledPolicy(myAddress);

                            final Set<Policy> devicePolicies = Set.of(controlledPolicy); // TODO: needs additional TunPolicy and not only ControlledPolicy?
                            final DeviceHello message = new DeviceHello(facts, devicePolicies);

                            for (DrasylAddress deviceAddress : myDeviceAddresses) {
                                // add this Device to the Devices Object
                                final Device thisDevice = new Device(deviceAddress, myAddress);
                                myDevices.addDevice(thisDevice);

                                // send the ControlledPolicy via a DeviceHello to the device
                                ((DrasylServerChannel) ctx.channel()).serve(deviceAddress).addListener((ChannelFutureListener) future -> {
                                    if (future.isSuccess()) {
                                        final Channel channelToController = future.channel();
                                        channelToController.writeAndFlush(message).addListener(FIRE_EXCEPTION_ON_FAILURE);
                                    }
                                    else {
                                        throw (Exception) future.cause();
                                    }
                                });
                            }
                        }
                        else if (policy instanceof ControlledPolicy) {
                            final ControlledPolicy controlledPolicy = (ControlledPolicy) policy;
                            final DrasylAddress controllerAddress = controlledPolicy.controller();
                            out.println("Received ControlledPolicy with the address of my new Controller.");
                            out.println("My Controller's Address is " + controllerAddress.toString());
                        }
                    }
                }
                else if (certificates.isEmpty() && !controllerHello.policies().isEmpty()) {
                    throw new CertificateException("No certificates although there are policies.");
                }
                else if (!certificates.isEmpty() && controllerHello.policies().isEmpty()) {
                    final String myNewCertificateString = certificates.get(0);
                    final CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(myNewCertificateString.getBytes()));
                    // TODO: set isSubController of the device that is sub-controller to true
                    out.println("Received certificate from controller.");
                }

                // set state to JOINED if it is not already
                if (state != JOINED) {
                    out.println("Registered!");
                }
                state = JOINED;

                // extract policies from the certificate?
                final Set<Policy> newPolicies = controllerHello.policies();
                LOG.trace("Got new policies from controller: {}", newPolicies);

                // remove old policies
                for (final Policy policy : policies) {
                    if (!newPolicies.contains(policy)) {
                        LOG.debug("Remove old policy: {}", policy);
                        policy.removePolicy(ctx.pipeline());
                    }
                }

                // add new policies
                for (final Policy newPolicy : newPolicies) {
                    if (!policies.contains(newPolicy)) {
                        LOG.debug("Add new policy: {}", newPolicy);
                        newPolicy.addPolicy(ctx.pipeline());
                    }
                }

                policies.clear();
                policies.addAll(newPolicies);
            }
        }
        else {
            ctx.fireUserEventTriggered(evt);
        }
    }

    private String createCSR(PublicKey publicKey, PrivateKey privateKey, String subnet) throws OperatorCreationException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        // create only subject info for future certificate
        final X500Name subjectName = new X500Name("CN=" + subnet);

        // create CSR builder
        final JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subjectName, publicKey);
        // create a content signer
        final ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(privateKey);
        // build the CSR
        final PKCS10CertificationRequest csr = csrBuilder.build(signer);

        return convertCSRToPemString(csr);
    }

    private static String convertCSRToPemString(final PKCS10CertificationRequest csr) throws IOException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8));
        final byte[] csrBytes = csr.getEncoded();
        return "-----BEGIN CERTIFICATE REQUEST-----" + "\n" + encoder.encodeToString(csrBytes) + "\n" + "-----END CERTIFICATE REQUEST-----";
    }

    enum State {
        INITIALIZED,
        JOINING,
        JOINED,
        CLOSING
    }
}
