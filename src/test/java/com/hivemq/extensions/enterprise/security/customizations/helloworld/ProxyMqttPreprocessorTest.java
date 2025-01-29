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

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.mqtt5.Mqtt5BlockingClient;
import com.hivemq.client.mqtt.mqtt5.exceptions.Mqtt5ConnAckException;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;
import org.testcontainers.hivemq.HiveMQContainer;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Dasha Samkova
 * @since 4.36.0
 */
class ProxyMqttPreprocessorTest {

    private static final @NotNull String ESE_ID = "hivemq-enterprise-security-extension";
    private static final @NotNull String ESE_NAME = "HiveMQ Enterprise Security Extension";
    private static final @NotNull String ESE_HOME_FOLDER = "/opt/hivemq/extensions/" + ESE_ID;

    private final @NotNull HiveMQContainer hivemq = new HiveMQContainer( //
            DockerImageName.parse("hivemq/hivemq4").withTag("latest")) //
            .withLogLevel(Level.DEBUG)
            .withLogConsumer(outputFrame -> System.out.print("HIVEMQ: " + outputFrame.getUtf8String()))
            .withCopyFileToContainer(MountableFile.forClasspathResource("/p-ese-config.xml"),
                    ESE_HOME_FOLDER + "/conf/config.xml")
            .withCopyFileToContainer(MountableFile.forClasspathResource("/p-ese-file-realm.xml"),
                    ESE_HOME_FOLDER + "/conf/file-realm.xml")
            .withCopyToContainer(proxyMqttPreprocessor(),
                    ESE_HOME_FOLDER +
                            "/customizations/" +
                            ProxyMqttPreprocessor.class.getSimpleName().toLowerCase(Locale.ROOT) +
                            ".jar")
            .withoutPrepackagedExtensions("hivemq-allow-all-extension");

    private static @NotNull Transferable proxyMqttPreprocessor() {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        ShrinkWrap.create(JavaArchive.class)
                .addClasses(ProxyMqttPreprocessor.class)
                .as(ZipExporter.class)
                .exportTo(out);
        return Transferable.of(out.toByteArray());
    }

    @AfterEach
    void afterEach() {
        hivemq.stop();
    }

    @Test
    void allowed() throws Exception {
        hivemq.start();

        hivemq.enableExtension(ESE_NAME, ESE_ID);
        final Mqtt5BlockingClient client = connect();
        client.disconnect();
    }

    @Test
    void notAllowed() throws Exception {
        hivemq.start();

        hivemq.enableExtension(ESE_NAME, ESE_ID);
        assertThatThrownBy(this::connect).isInstanceOf(Mqtt5ConnAckException.class)
                .hasMessage("CONNECT failed as CONNACK contained an Error Code: NOT_AUTHORIZED.");
    }

    private Mqtt5BlockingClient connect() {
        final Mqtt5BlockingClient client = MqttClient.builder()
                .useMqttVersion5()
                .serverPort(hivemq.getMqttPort())
                .simpleAuth()
                .username("my-user")
                .password("my-password".getBytes(StandardCharsets.UTF_8))
                .applySimpleAuth()
                .buildBlocking();
        client.connectWith().send();
        return client;
    }
}
