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
import org.drasyl.channel.DrasylChannel;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.sdon.config.ControlledPolicy;
import org.drasyl.cli.sdon.config.Device;
import org.drasyl.cli.sdon.config.Devices;
import org.drasyl.cli.sdon.config.Network;
import org.drasyl.cli.sdon.config.RunPolicy;
import org.drasyl.cli.sdon.config.SubControllerPolicy;
import org.drasyl.cli.sdon.config.Policy;
import org.drasyl.cli.sdon.config.TunPolicy;
import org.drasyl.cli.sdon.event.SdonMessageReceived;
import org.drasyl.cli.sdon.message.ControllerHello;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.cli.sdon.message.SdonMessage;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
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
    public IdentityPublicKey fallbackController;
    public IdentityPublicKey controller;
    public final Devices devices;
    public Boolean isSubController;
    public int nrIntendedDevices;
    public final PublicKey publicKey;
    public final PrivateKey privateKey;
    public X509Certificate myCert;
    public String myCertAsString;
    public List<String> myCertificateStrings;
    public String[] subnetSplit;
    public final Map<String, Object> facts;
    State state;
    public Set<Policy> policiesForMe = new HashSet<>();
    public Set<Policy> feedbackPolicies = new HashSet<>();
    public final Set<Policy> policiesForMyDevices = new HashSet<>();
    public Network network;
    private int waitingCounter;
    private int deregisteredDevices;

    public SdonDeviceHandler(final PrintStream out,
                             final IdentityPublicKey controller,
                             final Devices devices,
                             final java.security.PublicKey publicKey,
                             final PrivateKey privateKey,
                             final Map<String, Object> facts) {
        this.out = requireNonNull(out);
        this.controller = requireNonNull(controller);
        this.devices = requireNonNull(devices);
        this.isSubController = false;
        this.publicKey = requireNonNull(publicKey);
        this.privateKey = requireNonNull(privateKey);
        this.facts = requireNonNull(facts);
        this.deregisteredDevices = 0;
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
                        final DeviceHello hello = new DeviceHello(facts, feedbackPolicies, "");
                        LOG.debug("Send to {}: {}", controller, hello);
                        channel.writeAndFlush(hello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                    }
                }
            });

            ctx.executor().scheduleAtFixedRate(() -> {
                try {
                    if (isSubController) {
                        int minDevices = (int) facts.get("min_devices");
                        if (nrIntendedDevices - deregisteredDevices >= minDevices) {
                            // send ControllerHello messages to all the sub-controller's devices
                            for (Device device : devices.getDevices()) {
                                // here one could load individual policies for the different devices
                                final ControllerHello message = new ControllerHello(policiesForMyDevices, myCertificateStrings);
                                ((DrasylServerChannel) ctx.channel()).serve(device.address()).addListener((ChannelFutureListener) future -> {
                                    if (future.isSuccess()) {
                                        final Channel channelToController = future.channel();
                                        LOG.debug("Send to {}: {}.", device.address(), message.toString().replace("\n", ""));
                                        channelToController.writeAndFlush(message).addListener(FIRE_EXCEPTION_ON_FAILURE);
                                    }
                                    else {
                                        throw (Exception) future.cause();
                                    }
                                });
                            }
                            // update the devices in the SubControllerPolicy that will be sent back to the controller
                            for (Policy policy : feedbackPolicies) {
                                if (policy instanceof SubControllerPolicy) {
                                    ((SubControllerPolicy) policy).setDevices(devices.getDeviceAddresses());
                                }
                            }
                        }
                        else {
                            System.out.println("got no devices anymore!");
                            isSubController = false;
                            feedbackPolicies.clear();
                        }
                    }

                    // if the device has not received a message in a long time, it tries connecting to its fallbackController
                    if (waitingCounter >= 4) {
                        System.out.println("changed to FALLBACK-CONTROLLER!");
                        controller = fallbackController;
                    }
                    else {
                        waitingCounter++;
                    }

                    // send DeviceHello to the device's controller (or fallbackController)
                    ((DrasylServerChannel) ctx.channel()).serve(controller).addListener((ChannelFutureListener) future -> {
                        if (future.isSuccess()) {
                            if (state == JOINED) {
                                final Channel channel = future.channel();
                                final DeviceHello hello = new DeviceHello(facts, feedbackPolicies, "");
                                LOG.debug("Send to {}: {}", controller, hello);
                                channel.writeAndFlush(hello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                            }
                        }
                    });
                }
                catch (final Exception e) {
                    ctx.fireExceptionCaught(e);
                }
            }, randomInt(0, DEVICE_HELLO_INTERVAL), DEVICE_HELLO_INTERVAL, MILLISECONDS); // FIXME: maybe not the best intervals for ControllerHello's?
        }
    }

    @Override
    public void userEventTriggered(final ChannelHandlerContext ctx,
                                   final Object evt) throws Exception {
        if (evt instanceof SdonMessageReceived) {
            final DrasylAddress sender = ((SdonMessageReceived) evt).address();
            final SdonMessage msg = ((SdonMessageReceived) evt).msg();
            //out.println("----------------------------------------------------------------------------------------------");
            LOG.debug("Received from {}: {}", sender, msg.toString().replace("\n", ""));
            waitingCounter = 0;

            if (msg instanceof DeviceHello) { // --> device is sub-controller & gets message from its devices
                final DeviceHello deviceHello = (DeviceHello) msg;
                final Device device = devices.getOrCreateDevice(sender);

                device.setFacts(deviceHello.facts());
                device.setPolicies(deviceHello.policies());

                final DrasylChannel channel = ((DrasylServerChannel) ctx.channel()).getChannels().get(sender);
                if (device.isOffline()) {
                    channel.closeFuture().addListener((ChannelFutureListener) future -> {
                        device.setOffline();
                        out.println("Device " + sender + " deregistered.");
                        devices.removeDevice(device);
                        deregisteredDevices++;
                    });

                    device.setOnline();
                    out.println("Device " + sender + " registered.");

                    final ControllerHello controllerHello = new ControllerHello(Set.of(), myCertificateStrings);
                    LOG.debug("Send to {}: {}.", sender, controllerHello.toString().replace("\n", ""));
                    channel.writeAndFlush(controllerHello).addListener(FIRE_EXCEPTION_ON_FAILURE);
                }
            }
            else if (msg instanceof ControllerHello) { // --> device gets message from its controller
                final ControllerHello controllerHello = (ControllerHello) msg;
                final List<String> certificates = controllerHello.certificates();

                if (!certificates.isEmpty() && !controllerHello.policies().isEmpty()) {
                    // load rootCertificate from file & check whether it equals the last certificate in the message
                    final String rootCertFilePath = "cacert.crt"; // TODO: make this more dynamic (command inputs?)
                    final String rootCertString = Files.readString(Path.of(rootCertFilePath));
                    if (!(certificates.get(certificates.size() - 1).equals(rootCertString))) {
                        throw new CertificateException("Not the right root certificate!");
                    }

                    // check validity of received certificate chain
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

                    // check subnet address in the "first" certificate
                    final String certString = certificates.get(0);
                    final X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certString.getBytes()));
                    final X500Name subject = new JcaX509CertificateHolder(cert).getSubject();
                    final String subjectString = subject.toString();
                    final String[] subjectInfos = subjectString.split(",");
                    final String subnet = subjectInfos[0].substring(3);
                    out.println("Valid X.509 certificate for subnet " + subnet);
                    //LOG.debug("Valid X.509 certificate for subnet {}", subnet);
                    subnetSplit = subnet.split("/");
                    final InetAddress subnetAddress = InetAddress.getByName(subnetSplit[0]);
                    final byte[] subnetAddressBytes = subnetAddress.getAddress();
                    final short subnetNetmask = Short.parseShort(subnetSplit[1]);

                    // react to received policies
                    final Set<Policy> policies = controllerHello.policies();
                    Iterator<Policy> policyIterator = policies.iterator();
                    while (policyIterator.hasNext()){
                        Policy policy = policyIterator.next();
                        if (policy instanceof TunPolicy) {
                            final TunPolicy tunPolicy = (TunPolicy) policy;
                            final InetAddress ipAddress = tunPolicy.address();
                            final byte[] ipAddressBytes = ipAddress.getAddress();
                            //final short netmask = tunPolicy.netmask();

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
                                out.println("IP address from policy fits in the subnet specified in the controller's certificate!");
                                //LOG.debug("IP address from policy fits in the subnet specified in the controller's certificate!");
                            }
                            /*if (!(netmask == subnetNetmask)) {
                                throw new Exception("The netmask of the IP address from the policy is not the same as netmask from the controller's certificate.");
                            }*/
                        }
                        else if (policy instanceof SubControllerPolicy) { // the device is a sub-controller --> it receives SubControllerPolicies & sends ControlledPolicies to its devices
                            final SubControllerPolicy subControllerPolicy = (SubControllerPolicy) policy;
                            // sub-controller instantiation (create CSR & send it to controller) is done by the SubControllerPolicyHandler (called on the first SubControllerPolicy that is received)

                            // TODO: check if maximum amount of devices the sub-controller can hold has changed --> if so, change in facts:
                            //facts.replace("sub-controller max devices", actualNr);

                            // the sub-controller receives its own certificate only once & then the chain without it (until the controller's certificate)
                            final String myNewCertificateString = certificates.get(0);
                            //out.println("Received certificate: " + myNewCertificateString.replace("\n", "")); // DEBUG printing
                            if (myCertificateStrings == null) {
                                myCertificateStrings = certificates;
                            }
                            // to detect the one time the actual sub-controller's certificate is received, it is checked, whether the certificate candidate was already sent or is in the already sent certificate chain
                            if (!myNewCertificateString.equals(myCertAsString) && !myCertificateStrings.contains(myNewCertificateString)) {
                                myCertificateStrings = certificates;
                                myCertAsString = myNewCertificateString;
                                myCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(myNewCertificateString.getBytes()));
                                out.println("Accepted as my certificate: " + myNewCertificateString.replace("\n", "")); // DEBUG
                            }
                            out.println("----------------------------------------------------------------------------------------------");

                            // add ControlledPolicy to the policiesForMyDevices
                            final DrasylAddress myAddress = subControllerPolicy.address();
                            policiesForMyDevices.add(new ControlledPolicy(myAddress));

                            // TODO: do we need a callback for the sub-controller-net?
                            //network.callCallback(intendedDevices);
                        }
                        else if (policy instanceof RunPolicy && isSubController) {
                            final RunPolicy runPolicy = (RunPolicy) policy;
                            policiesForMyDevices.add(runPolicy);
                            policyIterator.remove();
                        }
                    }
                }
                else if (certificates.isEmpty() && !controllerHello.policies().isEmpty()) {
                    throw new CertificateException("No certificates although there are policies.");
                }

                // set state to JOINED if it is not already
                if (state != JOINED) {
                    out.println("Registered!");
                }
                state = JOINED;

                final Set<Policy> newPolicies = controllerHello.policies();
                LOG.debug("--- Got policies from controller: {}", newPolicies);

                // remove old policies
                for (final Policy policy : policiesForMe) {
                    if (!newPolicies.contains(policy)) {
                        LOG.debug("--- Remove old policy: {}", policy);
                        policy.removePolicy(ctx.pipeline());
                    }
                }

                // add new policies
                for (final Policy newPolicy : newPolicies) {
                    if (!policiesForMe.contains(newPolicy)) {
                        LOG.debug("--- Add new policy: {}", newPolicy);
                        newPolicy.addPolicy(ctx.pipeline());
                    }
                }

                //LOG.debug("PoliciesForMe1: " + policiesForMe);
                policiesForMe.clear();
                policiesForMe.addAll(newPolicies);
                //LOG.debug("PoliciesForMe2: " + policiesForMe);

                // add policies to feedbackPolicies & update devices in SubControllerPolicy (is properly empty)
                feedbackPolicies.clear();
                //feedbackPolicies = new HashSet<>(newPolicies);
                for (Policy policy : policiesForMe) {
                    if (policy instanceof SubControllerPolicy) {
                        SubControllerPolicy scPolicy = (SubControllerPolicy) policy;
                        SubControllerPolicy newPolicy = new SubControllerPolicy(scPolicy.address(), scPolicy.controller(), devices.getDeviceAddresses(), scPolicy.is_sub_controller(), scPolicy.subnetString(), scPolicy.myFunctionFileName());
                        feedbackPolicies.add(newPolicy);
                        //((SubControllerPolicy) policy).setDevices(devices.getDeviceAddresses());
                    }
                    else {
                        feedbackPolicies.add(policy);
                    }
                }

                //LOG.debug("FeedbackPolicies1: " + feedbackPolicies);
                //LOG.debug("PoliciesForMe3: " + policiesForMe);
            }
        }
        else {
            ctx.fireUserEventTriggered(evt);
        }
    }

    enum State {
        INITIALIZED,
        JOINING,
        JOINED,
        CLOSING
    }
}
