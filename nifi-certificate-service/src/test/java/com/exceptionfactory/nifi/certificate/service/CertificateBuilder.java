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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class CertificateBuilder {
    public static final X500Principal ISSUER = new X500Principal("CN=issuer");

    public static final BigInteger SERIAL_NUMBER = BigInteger.ONE;

    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";

    private static final String KEY_ALGORITHM = "RSA";

    private static final X500Principal SUBJECT = new X500Principal("CN=subject");

    private static final long ONE = 1;

    /**
     * Generate Key Pair using SHA-256 with RSA
     *
     * @return Key Pair
     * @throws NoSuchAlgorithmException Thrown on KeyPairGenerator.getInstance()
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        return generator.generateKeyPair();
    }

    /**
     * Generate X.509 Certificate using Key Pair
     *
     * @param keyPair Key Pair
     * @return X.509 Certificate
     * @throws OperatorCreationException Thrown on JcaContentSignerBuilder.build()
     * @throws CertificateException Thrown on JcaX509CertificateConverter.getCertificate()
     */
    public static X509Certificate generateCertificate(final KeyPair keyPair) throws OperatorCreationException, CertificateException {
        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();

        final Date start = new Date();
        final long endMilliseconds = Instant.now().plus(ONE, ChronoUnit.HOURS).toEpochMilli();
        final Date end = new Date(endMilliseconds);
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(ISSUER, SERIAL_NUMBER, start, end, SUBJECT, publicKey);

        final ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(privateKey);
        final X509CertificateHolder holder = builder.build(contentSigner);
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        return converter.getCertificate(holder);
    }
}
