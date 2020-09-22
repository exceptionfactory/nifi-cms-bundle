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
package com.exceptionfactory.nifi.cms;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.nifi.processor.exception.ProcessException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

/**
 * Algorithm Resolver for converting Algorithm string to ASN.1 Object Identifier
 */
public class AlgorithmResolver {

    private static final Class<?> ALGORITHM_CLASS = CMSAlgorithm.class;

    private static final String ALGORITHM_NOT_FOUND = "Algorithm [%s] Not Found in CMS Algorithms";

    private static final String ALGORITHM_NOT_READABLE = "Algorithm [%s] Not Readable in CMS Algorithms";

    /**
     * Get Algorithm Identifier based on field of CMSAlgorithm class
     *
     * @param algorithm Algorithm property
     * @return ASN.1 Object Identifier of Algorithm
     */
    public static ASN1ObjectIdentifier getAlgorithmIdentifier(final String algorithm) {
        final List<Field> algorithmFields = FieldUtils.getAllFieldsList(ALGORITHM_CLASS);
        final Optional<Field> algorithmField = algorithmFields.stream().filter(field -> field.getName().equals(algorithm)).findFirst();
        if (algorithmField.isPresent()) {
            try {
                return (ASN1ObjectIdentifier) FieldUtils.readDeclaredStaticField(ALGORITHM_CLASS, algorithm);
            } catch (final IllegalAccessException e) {
                final String message = String.format(ALGORITHM_NOT_READABLE, algorithm);
                throw new ProcessException(message);
            }
        } else {
            final String message = String.format(ALGORITHM_NOT_FOUND, algorithm);
            throw new ProcessException(message);
        }
    }
}
