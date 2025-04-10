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
package org.drasyl.cli.sdon.handler.policy;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.drasyl.channel.DrasylServerChannel;
import org.drasyl.cli.sdon.config.Device;
import org.drasyl.cli.sdon.config.Devices;
import org.drasyl.cli.sdon.config.NetworkConfig;
import org.drasyl.cli.sdon.config.NetworkNode;
import org.drasyl.cli.sdon.config.Policy;
import org.drasyl.cli.sdon.config.SubControllerPolicy;
import org.drasyl.cli.sdon.handler.SdonDeviceHandler;
import org.drasyl.cli.sdon.message.ControllerHello;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;
import org.drasyl.util.network.Subnet;
import org.luaj.vm2.LuaString;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static io.netty.channel.ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE;
import static java.util.Objects.requireNonNull;

public class SubControllerPolicyHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOG = LoggerFactory.getLogger(SubControllerPolicyHandler.class);
    private final SubControllerPolicy policy;

    public SubControllerPolicyHandler(final SubControllerPolicy policy) {
        this.policy = requireNonNull(policy);
    }

    @Override
    public void handlerAdded(final ChannelHandlerContext ctx) throws IOException, OperatorCreationException, CertificateException {
        // get DeviceHandler & add sub-controller facts
        final SdonDeviceHandler deviceHandler = ctx.pipeline().get(SdonDeviceHandler.class);
        deviceHandler.isSubController = true;
        deviceHandler.nrIntendedDevices = policy.devices().size();

        // fallback solution for when the sub-controller network config file does not specify the maxDevices & minDevices properly:
        int maxDevices = 10;
        int minDevices = 1;
        deviceHandler.facts.put("max_devices", maxDevices);
        deviceHandler.facts.put("min_devices", minDevices);

        System.out.println("------------------------------------------------------------------------------------------------");
        System.out.println("I am a SUB-CONTROLLER!");
        System.out.println("Intended devices: " + policy.devices().toString());
        System.out.println("Actual devices: " + deviceHandler.devices.getDeviceAddresses().toString());
        System.out.println("My controller is: " + policy.controller());
        System.out.println("------------------------------------------------------------------------------------------------");

        // create & send CSR in DeviceHello
        final String csrAsString = createCSR(deviceHandler.publicKey, deviceHandler.privateKey, new Subnet(policy.subnetString()));
        final DeviceHello subControllerCSR = new DeviceHello(Map.of(), Set.of(), csrAsString);
        System.out.println("Generated DeviceHello message with CSR. Sending to controller now.");
        ((DrasylServerChannel) ctx.channel()).serve(policy.controller()).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                final Channel channelToController = future.channel();
                LOG.debug("Send to {}: {}.", policy.controller(), subControllerCSR.toString().replace("\n", ""));
                channelToController.writeAndFlush(subControllerCSR).addListener(FIRE_EXCEPTION_ON_FAILURE);
            }
            else {
                throw (Exception) future.cause();
            }
        });

        // read myFunctionFileName & create a NetworkConfig & other variables with it
        try {
            final File configFile = new File(policy.myFunctionFileName());
            final NetworkConfig config = NetworkConfig.parseFile(configFile);
            deviceHandler.network = config.network();
            final Devices devices = new Devices();
            for (final DrasylAddress deviceAddress : policy.devices()) {
                final Device device = devices.getOrCreateDevice(deviceAddress, policy.address());
                device.setOnline();
            }
            LOG.debug("Read SubControllerNetworkConfig out of file.");

            // currently this is quite strict with how the MAX_DEVICE_NUMBER & MIN_DEVICE_NUMBER have to be specified in the config file
            final BufferedReader bufferedReader = new BufferedReader(new FileReader(configFile));
            final String firstLine = bufferedReader.readLine();
            final String secondLine = bufferedReader.readLine();
            if (firstLine.startsWith("MAX_DEVICE_NUMBER =") && secondLine.startsWith("MIN_DEVICE_NUMBER =")) {
                maxDevices = Integer.parseInt(firstLine.substring(firstLine.indexOf("=") + 2));
                minDevices = Integer.parseInt(secondLine.substring(secondLine.indexOf("=") + 2));
                LOG.debug("read from the configFile: maxDevices = {}, minDevices = {}", maxDevices, minDevices);
                deviceHandler.facts.put("max_devices", maxDevices);
                deviceHandler.facts.put("min_devices", minDevices);
            }

            // do matchmaking FIXME: should this be done here? why not in the deviceHandler?
            final Set<Device> assignedDevices = new HashSet<>();
            final Map<LuaString, NetworkNode> nodes = deviceHandler.network.getNodes();
            for (final Map.Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                final NetworkNode node = entry.getValue();

                Device bestMatch = null;
                int minDistance = Integer.MAX_VALUE;

                for (final Device device : devices.getDevices()) {
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
            LOG.debug("Matchmaking (nodes to devices) done.");

            // disseminate policies
            for (final Device device : devices.getDevices()) {
                NetworkNode node = null;
                for (final Map.Entry<LuaString, NetworkNode> entry : nodes.entrySet()) {
                    if (Objects.equals(entry.getValue().device(), device.address())) {
                        node = entry.getValue();
                    }
                }
                final Set<Policy> policies;
                if (node != null) {
                    policies = node.createPolicies();
                }
                else {
                    policies = Set.of();
                }
                deviceHandler.policiesForMyDevices.addAll(policies);
            }
        }
        catch (IOException e) {
            LOG.debug(e);
        }

        System.out.println("------------------------------------------------------------------------------------------------");
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        System.out.println("------------------------------------------------------------------------------------------------");
        System.out.println("I am NO LONGER sub-controller!");
        System.out.println("------------------------------------------------------------------------------------------------");

        // send reset message to all my devices
        final SdonDeviceHandler deviceHandler = ctx.pipeline().get(SdonDeviceHandler.class);
        deviceHandler.isSubController = false;
        final ControllerHello resetMsg = new ControllerHello(Set.of(), deviceHandler.myCertificateStrings);
        for (DrasylAddress devAddress : policy.devices()) {
            ((DrasylServerChannel) ctx.channel()).serve(devAddress).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    final Channel channelToController = future.channel();
                    LOG.debug("Send to {}: {}.", devAddress, resetMsg.toString().replace("\n", ""));
                    channelToController.writeAndFlush(resetMsg).addListener(FIRE_EXCEPTION_ON_FAILURE);
                }
                else {
                    throw (Exception) future.cause();
                }
            });
        }
    }

    private String createCSR(PublicKey publicKey, PrivateKey privateKey, Subnet subnet) throws OperatorCreationException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        // create only subject info for future certificate
        final X500Name subjectName = new X500Name("CN=" + subnet.toString());

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
}
