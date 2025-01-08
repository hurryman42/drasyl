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
package org.drasyl.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.drasyl.crypto.Crypto;
import org.drasyl.crypto.CryptoException;
import org.drasyl.crypto.sodium.DrasylSodiumWrapper;
import org.drasyl.identity.Identity;
import org.drasyl.identity.IdentityPublicKey;
import org.drasyl.identity.IdentitySecretKey;
import org.drasyl.identity.KeyAgreementPublicKey;
import org.drasyl.identity.KeyAgreementSecretKey;
import org.drasyl.identity.KeyPair;
import org.drasyl.identity.ProofOfWork;
import org.drasyl.node.identity.IdentityManager;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import static java.util.Objects.requireNonNull;
import static org.drasyl.cli.CreateCSR.LINE_SEPARATOR;
import static org.drasyl.crypto.Crypto.INSTANCE;
import static org.drasyl.crypto.sodium.DrasylSodiumWrapper.ED25519_PUBLICKEYBYTES;
import static org.drasyl.crypto.sodium.DrasylSodiumWrapper.ED25519_SECRETKEYBYTES;
import static org.drasyl.identity.Identity.POW_DIFFICULTY;

public class GenerateIdentity {
    public static final String BEGIN_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_KEY = "-----END PRIVATE KEY-----";

    private static final DrasylSodiumWrapper sodium = INSTANCE.getSodium();

    /**
     * Generates a ED25519 key pair, saves it into two PEM files and uses it to create a drasyl Identity
     *
     * @param args a string array consisting of the file names for the to be created public and private key (without file endings)
     * @throws IOException thrown when something goes wrong with reading the files
     * @throws NoSuchAlgorithmException thrown when the desired algorithm cannot be found
     */
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final String publicKeyFileName = args[0];
        final String privateKeyFileName = args[1];
        final String identityFilePath = args[2];

        // generate the keys
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        final java.security.KeyPair keyPairED25519 = keyPairGenerator.generateKeyPair();
        final PublicKey publicKey = keyPairED25519.getPublic();
        final PrivateKey privateKey = keyPairED25519.getPrivate();

        // save the keys to files
        writeKeyToFile("PUBLIC KEY", publicKey.getEncoded(), publicKeyFileName + ".pem");
        writeKeyToFile("PRIVATE KEY", privateKey.getEncoded(), privateKeyFileName + ".key");

        final String privateKeyPEM = Files.readString(Path.of(privateKeyFileName + ".key"));
        System.out.println(privateKeyPEM);
        final byte[] secretKeyBytes = convertSecretKeyEd25519(privateKeyPEM);
        final byte[] publicKeyBytes = publicKeyFromSecretKey(secretKeyBytes);

        System.out.println(new String(publicKeyBytes));

        final IdentitySecretKey idSecKey = IdentitySecretKey.of(secretKeyBytes);
        final IdentityPublicKey idPubKey = IdentityPublicKey.of(publicKeyBytes);
        final ProofOfWork pow = ProofOfWork.generateProofOfWork(idPubKey, POW_DIFFICULTY);
        final KeyPair<IdentityPublicKey, IdentitySecretKey> identityKeyPair = KeyPair.of(idPubKey, idSecKey);
        final KeyPair<KeyAgreementPublicKey, KeyAgreementSecretKey> agreementKeyPair = Crypto.INSTANCE.convertLongTimeKeyPairToKeyAgreementKeyPair(identityKeyPair);
        final Identity id = Identity.of(pow, identityKeyPair, agreementKeyPair);

        IdentityManager.writeIdentityFile(Path.of(identityFilePath), id);
    }

    public static byte[] convertSecretKeyEd25519(final String secretKey) throws CryptoException {
        requireNonNull(secretKey);
        if (!isValidKeyFormat(secretKey)) {
            throw new CryptoException("Invalid key format");
        }

        final Base64.Decoder decoder = Base64.getMimeDecoder();
        final String cert = secretKey.replace(BEGIN_KEY, "")
                .replace(END_KEY, "")
                .replace(LINE_SEPARATOR, "")
                .trim();

        final byte[] seed = extractRawKey(decoder.decode(cert));

        final byte[] publicKey = new byte[ED25519_PUBLICKEYBYTES];
        final byte[] ed25519sk = new byte[ED25519_SECRETKEYBYTES];

        final boolean success = sodium.fullSecretKeyFromSeed(publicKey, ed25519sk, seed);

        if (!success) {
            throw new CryptoException("Could not convert this key: " + secretKey);
        }

        return ed25519sk;
    }

    public static byte[] publicKeyFromSecretKey(final byte[] secretKey) throws CryptoException {
        requireNonNull(secretKey);
        return Arrays.copyOfRange(secretKey, ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES);
    }

    private static byte[] extractRawKey(final byte[] key) {
        final byte[] rawKey = new byte[32];
        System.arraycopy(key, key.length - 32, rawKey, 0, rawKey.length);

        return rawKey;
    }

    private static boolean isValidKeyFormat(final String key) {
        if (key == null) {
            return false;
        }
        final String trimmedPem = key.trim();
        return trimmedPem.startsWith(BEGIN_KEY) && trimmedPem.endsWith(END_KEY);
    }

    private static void writeKeyToFile(String description, byte[] keyBytes, String filename) throws IOException {
        final PemObject pemObjectPublicKey = new PemObject(description, keyBytes);
        final PemWriter pemWriterPublicKey = new PemWriter(new FileWriter(filename));
        pemWriterPublicKey.writeObject(pemObjectPublicKey);
        pemWriterPublicKey.close();
    }
}
