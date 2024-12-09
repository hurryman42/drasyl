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
package org.drasyl.cli.sdon.config;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.drasyl.cli.util.LuaHelper;
import org.drasyl.identity.DrasylAddress;
import org.drasyl.identity.IdentityPublicKey;
import org.luaj.vm2.LuaString;
import org.luaj.vm2.LuaTable;
import org.luaj.vm2.LuaValue;
import org.luaj.vm2.ast.Str;

import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Represents a network node.
 */
public class NetworkNode extends LuaTable {
    private final Network network;

    NetworkNode(final Network network, final LuaString name, final LuaTable params) {
        this.network = requireNonNull(network);

        // name
        set("name", name);

        // ip
        LuaValue ip = params.get("ip");
        if (ip == NIL) {
            ip = LuaValue.valueOf(network.getNextIp());
        }
        set("ip", ip);
    }

    @Override
    public String toString() {
        final LuaTable stringTable = tableOf();
        stringTable.set("name", get("name"));
        stringTable.set("ip", get("ip"));
        return "Node" + LuaHelper.toString(stringTable);
    }

    @Override
    public int hashCode() {
        return LuaHelper.hash(this);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final NetworkNode that = (NetworkNode) o;
        return Objects.equals(get("name"), that.get("name"));
    }

    public DrasylAddress name() {
        return IdentityPublicKey.of(get("name").tojstring());
    }

    public int getDistance(final Device device) {
        // FIXME: implement
        return device.isOnline() ? 1 : Integer.MAX_VALUE;
    }

    public void setDevice(final Device device) {
        set("device", LuaString.valueOf(device.address().toString()));
    }

    public DrasylAddress device() {
        if (get("device") != NIL) {
            return IdentityPublicKey.of(get("device").tojstring());
        }
        return null;
    }

    public Set<Policy> createPolicies() {
        try {
            final Set<Policy> policies = new HashSet<>();

            final Set<NetworkLink> links = network.getNodeLinks().get(get("name"));
            final Map<LuaString, NetworkNode> nodes = network.getNodes();

            // TunPolicy
            final String ipString = get("ip").tojstring();
            final String[] parts = ipString.split("/", 2);
            final InetAddress ipAddress = InetAddress.getByName(parts[0]);
            final short ipNetmask = Short.valueOf(parts[1]);
            final Map<InetAddress, DrasylAddress> mapping = new HashMap<>();
            for (final NetworkLink link : links) {
                final LuaString peerName = link.other(get("name").checkstring());
                final NetworkNode peer = nodes.get(peerName);
                final DrasylAddress peerAddress = peer.device();
                if (peerAddress != null) {
                    final InetAddress peerIpAddress = InetAddress.getByName(peer.get("ip").tojstring().split("/", 2)[0]);
                    mapping.put(peerIpAddress, peerAddress);
                }
            }

            final Policy tunPolicy = new TunPolicy(ipAddress, ipNetmask, mapping);
            policies.add(tunPolicy);

            return policies;
        }
        catch (final UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public List<String> loadCertificates(String certFilePath) throws IOException {
        List<String> certificates = new ArrayList<>();
        String certsString = Files.readString(Path.of(certFilePath));
        String[] certs = certsString.split("-----END CERTIFICATE-----");
        for (int i=0; i<(certs.length-1); i++) {
            String cert = certs[i] + "-----END CERTIFICATE-----\n";
            if (cert.startsWith("\n")) {
                cert = cert.substring(1);
            }
            certificates.add(cert);
        }
        /*PEMParser pemParserCerts = new PEMParser(new FileReader(certFilePath));
        Object object;
        while ((object = pemParserCerts.readObject()) != null) {
            if (object instanceof X509CertificateHolder) {
                X509Certificate certificate = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) object);
                String certificateString = convertCertToPem(certificate);
                certificates.add(certificateString);
            }
        }*/
        return certificates;
    }

    /**
     * Converts the given {@code certificate} to a PEM-encoded string representation.
     *
     * @param certificate the certificate to encode
     * @return PEM-encoded certificate as a String
     * @throws CertificateEncodingException if an encoding error occurs.
     */
    public static String convertCertToPem(final X509Certificate certificate) throws CertificateEncodingException {
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8));
        final byte[] cert = certificate.getEncoded();
        return "-----END CERTIFICATE-----" + "\n" + encoder.encodeToString(cert) + "\n" + "-----END PRIVATE KEY-----";
    }
}