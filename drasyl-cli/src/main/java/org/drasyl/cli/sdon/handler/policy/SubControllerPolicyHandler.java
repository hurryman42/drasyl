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
import org.drasyl.cli.sdon.config.SubControllerPolicy;
import org.drasyl.cli.sdon.handler.SdonDeviceHandler;
import org.drasyl.cli.sdon.message.DeviceHello;
import org.drasyl.util.logging.Logger;
import org.drasyl.util.logging.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
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
        final SdonDeviceHandler deviceHandler = ctx.pipeline().get(SdonDeviceHandler.class);

        final String myNewCertificateString = deviceHandler.myCertificateStrings.get(0);
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        deviceHandler.myCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(myNewCertificateString.getBytes()));
        System.out.println("Received signed certificate from controller.");

        if (deviceHandler.myCert == null) {
            // create CSR
            final String csrAsString = createCSR(deviceHandler.publicKey, deviceHandler.privateKey, policy.subnet());
            final DeviceHello subControllerCSR = new DeviceHello(Map.of(), Set.of() ,csrAsString);
            System.out.println("Generated DeviceHello message with CSR. Sending to controller now.");

            // send the CSR message
            ((DrasylServerChannel) ctx.channel()).serve(policy.controller()).addListener((ChannelFutureListener) future -> {
                if (future.isSuccess()) {
                    final Channel channelToController = future.channel();
                    channelToController.writeAndFlush(subControllerCSR).addListener(FIRE_EXCEPTION_ON_FAILURE);
                }
                else {
                    throw (Exception) future.cause();
                }
            });
        }
    }

    @Override
    public void handlerRemoved(final ChannelHandlerContext ctx) {
        // NOOP
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
}
