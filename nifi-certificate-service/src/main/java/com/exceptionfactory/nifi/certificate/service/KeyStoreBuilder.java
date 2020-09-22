/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.exceptionfactory.nifi.certificate.service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Key Store Builder with RuntimeException wrapping of Exceptions
 */
public class KeyStoreBuilder {
    private static final String TYPE_FAILED = "Key Store Instance Type [%s] instantiation failed";

    private static final String PATH_FAILED = "Key Store Path [%s] not found";

    private static final String READ_FAILED = "Key Store File [%s] read failed";

    private static final String LOAD_FAILED = "Key Store [%s] Type [%s] load failed";

    private String path;

    private String type = KeyStore.getDefaultType();

    private char[] password;

    /**
     * Set Key Store Path
     *
     * @param path Key Store Path on filesystem
     */
    public void setPath(final String path) {
        this.path = path;
    }

    /**
     * Set Key Store Type
     *
     * @param type Key Store Type either JKS or PKCS12
     */
    public void setType(final String type) {
        this.type = type;
    }

    /**
     * Set Key Store Password
     *
     * @param password Key Store Password
     */
    public void setPassword(final char[] password) {
        this.password = password;
    }

    /**
     * Build Key Store from properties and wrap Exceptions
     *
     * @return Key Store
     */
    public KeyStore build() {
        final KeyStore keyStore = getInstance();

        try (final InputStream inputStream = getInputStream()) {
            keyStore.load(inputStream, password);
        } catch (final IOException e) {
            final String message = String.format(READ_FAILED, path);
            throw new UncheckedIOException(message, e);
        } catch (final CertificateException | NoSuchAlgorithmException e) {
            final String message = String.format(LOAD_FAILED, path, type);
            throw new IllegalArgumentException(message, e);
        }

        return keyStore;
    }

    private InputStream getInputStream() {
        try {
            return new FileInputStream(path);
        } catch (final FileNotFoundException e) {
            final String message = String.format(PATH_FAILED, path);
            throw new UncheckedIOException(message, e);
        }
    }

    private KeyStore getInstance() {
        try {
            return KeyStore.getInstance(type);
        } catch (final KeyStoreException e) {
            final String message = String.format(TYPE_FAILED, type);
            throw new IllegalArgumentException(message, e);
        }
    }
}
