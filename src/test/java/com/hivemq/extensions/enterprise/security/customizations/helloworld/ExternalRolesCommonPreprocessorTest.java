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
import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5BlockingClient;
import com.hivemq.client.mqtt.mqtt5.exceptions.Mqtt5SubAckException;
import org.assertj.core.api.Assertions;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;
import org.testcontainers.containers.Network;
import org.testcontainers.hivemq.HiveMQContainer;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;
import software.xdev.mockserver.client.MockServerClient;
import software.xdev.testcontainers.mockserver.containers.MockServerContainer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static software.xdev.mockserver.model.HttpRequest.request;
import static software.xdev.mockserver.model.HttpResponse.response;

/**
 * @author Mario Schwede
 * @since 4.36.0
 */
@Testcontainers
class ExternalRolesCommonPreprocessorTest {

    private static final @NotNull String ESE_ID = "hivemq-enterprise-security-extension";
    private static final @NotNull String ESE_NAME = "HiveMQ Enterprise Security Extension";
    private static final @NotNull String ESE_HOME_FOLDER = "/opt/hivemq/extensions/" + ESE_ID;

    private final @NotNull Network network = Network.newNetwork();

    @Container
    private final @NotNull MockServerContainer mockServer =
            new MockServerContainer().withNetworkAliases("mockserver").withNetwork(network);

    @Container
    private final @NotNull HiveMQContainer hivemq = new HiveMQContainer( //
            DockerImageName.parse("hivemq/hivemq4").withTag("latest")) //
            .withLogLevel(Level.DEBUG)
            .withNetwork(network)
            .withNetworkAliases("hivemq")
            .withEnv("ROLES_ENDPOINT", "http://mockserver:" + MockServerContainer.PORT)
            .withLogConsumer(outputFrame -> System.out.print("HIVEMQ: " + outputFrame.getUtf8String()))
            .withCopyFileToContainer(MountableFile.forClasspathResource("/external-roles-config.xml"),
                    ESE_HOME_FOLDER + "/conf/config.xml")
            .withCopyFileToContainer(MountableFile.forClasspathResource("/external-roles-file-realm.xml"),
                    ESE_HOME_FOLDER + "/conf/file-realm.xml")
            .withCopyToContainer(externalRolesCommonPreprocessor(),
                    ESE_HOME_FOLDER +
                            "/customizations/" +
                            ExternalRolesCommonPreprocessor.class.getSimpleName().toLowerCase(Locale.ROOT) +
                            ".jar")
            .withoutPrepackagedExtensions("hivemq-allow-all-extension");

    private static @NotNull Transferable externalRolesCommonPreprocessor() {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        ShrinkWrap.create(JavaArchive.class)
                .addClasses(ExternalRolesCommonPreprocessor.class)
                .as(ZipExporter.class)
                .exportTo(out);
        return Transferable.of(out.toByteArray());
    }

    @Test
    void authorize() throws Exception {
        hivemq.enableExtension(ESE_NAME, ESE_ID);

        try (MockServerClient mockServerClient = new MockServerClient( //
                mockServer.getHost(), mockServer.getServerPort())) {
            mockServerClient.when(request("/").withQueryStringParameter("user", "my-user").withMethod("GET"))
                    .respond(response().withBody("external-role-1,external-role-2"));

            final Mqtt5BlockingClient mqttClient = connect();
            mqttClient.subscribeWith().topicFilter("internal-role-1").qos(MqttQos.AT_MOST_ONCE).send();
            mqttClient.subscribeWith().topicFilter("internal-role-2").qos(MqttQos.AT_MOST_ONCE).send();
            mqttClient.subscribeWith().topicFilter("external-role-1").qos(MqttQos.AT_MOST_ONCE).send();
            mqttClient.subscribeWith().topicFilter("external-role-2").qos(MqttQos.AT_MOST_ONCE).send();

            Assertions.assertThatThrownBy(() -> mqttClient.subscribeWith()
                            .topicFilter("unknown-role")
                            .qos(MqttQos.AT_MOST_ONCE)
                            .send()) //
                    .isInstanceOf(Mqtt5SubAckException.class).hasMessage("SUBACK contains only Error Codes");

            mockServerClient.verify(1, request("/") //
                    .withQueryStringParameter("user", "my-user"));
        }
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
