/*
 * Copyright 2024-present HiveMQ GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hivemq.extensions.enterprise.security.customizations.helloworld;

import com.codahale.metrics.Counter;
import com.codahale.metrics.MetricRegistry;
import com.hivemq.extension.sdk.api.client.parameter.ProxyInformation;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessor;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorInitInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorProcessInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorProcessOutput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorShutdownInput;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.Map;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;


import static java.util.Objects.requireNonNull;

/**
 * This example {@link MqttPreprocessor} only allows clients with specific IPs to connect.
 * This custom preprocessor is meant to be used as {@code <authentication-preprocessor>}.
 * <p>
 * The preprocessor performs the following computational steps:
 * <ol>
 *     <li>Reads proxy infos from the client connection information.</li>
 *     <li>Checks if the mqtt-username matches the given name.</li>
 *     <li>When the mqtt-username does not match, the ESE variables {@code authentication-key}
 *     and {@code authentication-byte-secret} are set to {@code null}.</li>
 *     <li>When the mqtt-username matches, the ESE variable {@code authentication-key}
 *     is set to {@code givenName}.</li>
 * </ol>
 * An example {@code p-config.xml} file that enables this preprocessor is provided in {@code src/test/resources}.
 *
 * @author Dasha Samkova
 * @since 4.36.0
 */
public class ProxyMqttPreprocessor implements MqttPreprocessor {

    private static final @NotNull Logger LOGGER = LoggerFactory.getLogger(ProxyMqttPreprocessor.class);

    private @Nullable Counter allowCounter;
    private @Nullable Counter denyCounter;

    @Override
    public void init(final @NotNull MqttPreprocessorInitInput input) {
        LOGGER.debug("INIT");

        allowCounter = input.getMetricRegistry()
                .counter(MetricRegistry.name(ProxyMqttPreprocessor.class, "ip", "allow", "count"));
        denyCounter = input.getMetricRegistry()
                .counter(MetricRegistry.name(ProxyMqttPreprocessor.class, "ip", "deny", "count"));
    }

    @Override
    public void process(
            final @NotNull MqttPreprocessorProcessInput input,
            final @NotNull MqttPreprocessorProcessOutput output) {
        LOGGER.debug("PROCESS");

        try {

            final @com.hivemq.extension.sdk.api.annotations.NotNull Optional<ProxyInformation>
                    pi = input.getConnectionInformation().getProxyInformation();
            LOGGER.info("ProxyInformation - Client Id: " + input.getClientInformation().getClientId());
            LOGGER.info("ProxyInformation - InetAddress: " + input.getConnectionInformation().getInetAddress());
            LOGGER.info("ProxyInformation - MqttVersion: " + input.getConnectionInformation().getMqttVersion());
            LOGGER.info("ProxyInformation - Is Proxy Information present? " + pi.isPresent());
            if (pi.isPresent()) {
                LOGGER.info("ProxyInformation - ProxyAddress: " + pi.get().getProxyAddress());
                LOGGER.info("ProxyInformation - ProxyPort: " + pi.get().getProxyPort());
                LOGGER.info("ProxyInformation - RawTLVs: " + pi.get().getRawTLVs());
                LOGGER.info("ProxyInformation - SourceAddress: " + pi.get().getSourceAddress());
                LOGGER.info("ProxyInformation - SourcePort: " + pi.get().getSourcePort());
                LOGGER.info("ProxyInformation - SslCertificateCN: " + pi.get().getSslCertificateCN());
                LOGGER.info("ProxyInformation - TlsVersion: " + pi.get().getTlsVersion());

                Map<Byte, ByteBuffer> tlvs = pi.get().getRawTLVs();
                // Read TLV with type 0xE0 (replace with the correct byte value)
                ByteBuffer givenNameBuffer = tlvs.get((byte) 0xE0);
                if (givenNameBuffer == null) {
                    output.getEseVariablesOutput().setAuthenticationKey(null);
                    output.getEseVariablesOutput().setAuthenticationByteSecret(null);

                    requireNonNull(denyCounter).inc();
                    LOGGER.debug("DENIED CLIENT ID: {} – ProxyInformation TLV 0xE0 is NOT present."
                            , input.getClientInformation().getClientId());
                } else {
                    String givenName = StandardCharsets.UTF_8.decode(givenNameBuffer).toString();
                    String mqttUsername = input.getEseVariablesInput().getAuthenticationKey().get();

                    if (givenName.equals(mqttUsername)) {
                        requireNonNull(allowCounter).inc();
                        LOGGER.debug("ALLOWED CLIENT ID: {} where username equals TLV 0xE0: {}"
                                , input.getClientInformation().getClientId(), givenName);
                    } else {
                        output.getEseVariablesOutput().setAuthenticationKey(null);
                        output.getEseVariablesOutput().setAuthenticationByteSecret(null);

                        requireNonNull(denyCounter).inc();
                        LOGGER.debug("DENIED CLIENT ID: {}, username: {}, TLV 0xE0: {}"
                                , input.getClientInformation().getClientId()
                                , mqttUsername
                                , givenName);

                    }
                }
            }else {
                output.getEseVariablesOutput().setAuthenticationKey(null);
                output.getEseVariablesOutput().setAuthenticationByteSecret(null);

                requireNonNull(denyCounter).inc();
                LOGGER.debug("DENIED CLIENT ID: {} – ProxyInformation is NOT present.", input.getClientInformation().getClientId());
            }
        } catch (final RuntimeException e) {
            LOGGER.warn("PROCESS FAILED", e);
        }
    }

    @Override
    public void shutdown(final @NotNull MqttPreprocessorShutdownInput input) {
        LOGGER.debug("SHUTDOWN");
    }
}
