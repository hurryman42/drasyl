/*
 * Copyright (c) 2020.
 *
 * This file is part of drasyl.
 *
 *  drasyl is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  drasyl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with drasyl.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.drasyl.identity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.drasyl.DrasylNodeConfig;
import org.drasyl.crypto.Crypto;
import org.drasyl.crypto.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import static java.util.Objects.requireNonNull;

/**
 * This class provides the identity of the node. Messages to the node are addressed to the identity.
 * In a future release, messages will be signed and encrypted with public-private key pairs
 * contained in the identity.
 */
public class IdentityManager {
    private static final Logger LOG = LoggerFactory.getLogger(IdentityManager.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final DrasylNodeConfig config;
    private PrivateIdentity identity;

    /**
     * Manages the identity at the specified file path. If there is no identity at this file path
     * yet, a new one is created.
     */
    public IdentityManager(DrasylNodeConfig config) {
        this(config, null);
    }

    IdentityManager(DrasylNodeConfig config, PrivateIdentity identity) {
        this.config = config;
        this.identity = identity;
    }

    /**
     * Attempts to load the identity defined in the configuration: First it tries to read the key
     * pair directly from the configuration. If no key pair is specified there, the identity is
     * loaded from the identity file path specified in the configuration. If the file does not
     * exist, a new identity is generated and written to the file. If all this fails and no identity
     * can be loaded, an {@link IdentityManagerException} is thrown.
     *
     * @throws IdentityManagerException
     */
    public void loadOrCreateIdentity() throws IdentityManagerException {
        if (config.getIdentityPublicKey() != null && config.getIdentityPrivateKey() != null) {
            LOG.debug("Load identity specified in config");
            try {
                this.identity = new PrivateIdentity(Address.of(config.getIdentityPublicKey()), config.getIdentityPublicKey(), config.getIdentityPrivateKey());
            }
            catch (IllegalArgumentException e) {
                throw new IdentityManagerException("Identity read from configuration seems invalid: " + e.getMessage());
            }
        }
        else {
            Path path = config.getIdentityPath();

            if (isIdentityFilePresent(path)) {
                LOG.debug("Read Identity from file '{}'", path);
                this.identity = readIdentityFile(path);
            }
            else {
                LOG.debug("No Identity present. Generate a new one and write to file '{}'", path);
                PrivateIdentity myIdentity = generateIdentity();
                writeIdentityFile(path, myIdentity);
                this.identity = myIdentity;
            }
        }
    }

    /**
     * Returns <code>true</code> if the identity file <code>path</code> exists. Otherwise
     * <code>false</code> is returned.
     *
     * @param path
     * @return
     */
    private static boolean isIdentityFilePresent(Path path) {
        return path.toFile().exists() && path.toFile().isFile();
    }

    /**
     * Reads the identity from <code>path</code>. Throws <code>IdentityManagerException</code> if
     * file cannot be read or file has unexpected content.
     *
     * @param path
     * @return
     * @throws IdentityManagerException
     */
    private static PrivateIdentity readIdentityFile(Path path) throws IdentityManagerException {
        try {
            CompressedKeyPair keyPair = OBJECT_MAPPER.readValue(path.toFile(), CompressedKeyPair.class);
            return new PrivateIdentity(Address.of(keyPair.getPublicKey()), keyPair.getPublicKey(), keyPair.getPrivateKey());
        }
        catch (JsonProcessingException e) {
            throw new IdentityManagerException("Unable to load identity from file '" + path + "': " + e.getMessage());
        }
        catch (IOException e) {
            throw new IdentityManagerException("Unable to access identity file '" + path + "': " + e.getMessage());
        }
    }

    /**
     * Generates a new random identity.
     *
     * @return
     * @throws IdentityManagerException
     */
    private static PrivateIdentity generateIdentity() throws IdentityManagerException {
        try {
            KeyPair newKeyPair = Crypto.generateKeys();
            CompressedPublicKey publicKey = CompressedPublicKey.of(newKeyPair.getPublic());
            CompressedPrivateKey privateKey = CompressedPrivateKey.of(newKeyPair.getPrivate());
            return new PrivateIdentity(Address.of(publicKey), publicKey, privateKey);
        }
        catch (CryptoException e) {
            throw new IdentityManagerException("Unable to generate new identity: " + e.getMessage());
        }
    }

    /**
     * Writes the identity <code>keyPair</code> to the file <code>path</code>. Attention: If
     * <code>path</code> already contains an identity, it will be overwritten without warning.
     *
     * @param path
     * @param identity
     * @throws IdentityManagerException
     */
    private static void writeIdentityFile(Path path,
                                          PrivateIdentity identity) throws IdentityManagerException {
        File file = path.toFile();

        if (Files.isDirectory(path) || (file.getParentFile() != null && !file.getParentFile().exists())) {
            throw new IdentityManagerException("Identity path '" + path + "' is a directory or path does not exist");
        }
        else if (file.exists() && !file.canWrite()) {
            throw new IdentityManagerException("Identity path '" + path + "' is not writable");
        }
        else {
            try {
                IdentityManager.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValue(file, identity.getKeyPair());
            }
            catch (IOException e) {
                throw new IdentityManagerException("Unable to write identity to file '" + path + "': " + e.getMessage());
            }
        }
    }

    public Address getAddress() {
        return identity.getAddress();
    }

    /**
     * @return returns the node identity.
     */
    public PrivateIdentity getIdentity() {
        return requireNonNull(identity);
    }

    public Identity getNonPrivateIdentity() {
        return identity.toNonPrivate();
    }

    /**
     * Deletes the identity file specified in the configuration.
     * <p>
     * ATTENTION: Messages directed to the present identity can then no longer be decrypted and
     * read. This step is irreversible. Should only be used if the present identity should never be
     * used again!
     */
    public static void deleteIdentityFile(Path path) throws IdentityManagerException {
        File file = path.toFile();

        if (!file.exists()) {
            // nothing to do
            return;
        }

        try {
            Files.delete(path);
        }
        catch (IOException e) {
            throw new IdentityManagerException("Unable to delete identity file '" + path + "': " + e.getMessage());
        }
    }
}
