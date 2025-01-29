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
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessor;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorInitInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorProcessInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorProcessOutput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.MqttPreprocessorShutdownInput;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * This example {@link MqttPreprocessor} only allows clients with specific IPs to connect.
 * This custom preprocessor is meant to be used as {@code <authentication-preprocessor>}.
 * <p>
 * The preprocessor performs the following computational steps:
 * <ol>
 *     <li>Reads the client IP from the client connection information.</li>
 *     <li>Checks if the client IP is part of the configured IP allowlist.</li>
 *     <li>When the client IP is not part of the IP allowlist, the ESE variables {@code authentication-key}
 *     and {@code authentication-byte-secret} are set to {@code null}.</li>
 * </ol>
 * An example {@code ip-allowlist-config.xml} file that enables this preprocessor is provided in {@code src/test/resources}.
 *
 * @author Mario Schwede
 * @since 4.36.0
 */
public class IpAllowlistMqttPreprocessor implements MqttPreprocessor {

    private static final @NotNull Logger LOGGER = LoggerFactory.getLogger(IpAllowlistMqttPreprocessor.class);

    private @Nullable Counter ipAllowCounter;
    private @Nullable Counter ipDenyCounter;
    private @Nullable Set<String> ipAllowlist;

    @Override
    public void init(final @NotNull MqttPreprocessorInitInput input) {
        LOGGER.debug("INIT");

        ipAllowCounter = input.getMetricRegistry()
                .counter(MetricRegistry.name(IpAllowlistMqttPreprocessor.class, "ip", "allow", "count"));
        ipDenyCounter = input.getMetricRegistry()
                .counter(MetricRegistry.name(IpAllowlistMqttPreprocessor.class, "ip", "deny", "count"));
        ipAllowlist = Set.copyOf(input.getCustomSettings().getAllForName("ipAllowlist"));
    }

    @Override
    public void process(
            final @NotNull MqttPreprocessorProcessInput input,
            final @NotNull MqttPreprocessorProcessOutput output) {
        LOGGER.debug("PROCESS");

        try {
            final String clientIp =
                    input.getConnectionInformation().getInetAddress().map(InetAddress::getHostAddress).orElse(null);
            if (clientIp != null && requireNonNull(ipAllowlist).contains(clientIp)) {
                requireNonNull(ipAllowCounter).inc();
                LOGGER.debug("ALLOWED CLIENT IP: {}", clientIp);
            } else {
                output.getEseVariablesOutput().setAuthenticationKey(null);
                output.getEseVariablesOutput().setAuthenticationByteSecret(null);

                requireNonNull(ipDenyCounter).inc();
                LOGGER.debug("UNKNOWN CLIENT IP: {}", clientIp);
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
