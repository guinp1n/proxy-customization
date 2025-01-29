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

import com.hivemq.extension.sdk.api.async.Async;
import com.hivemq.extensions.enterprise.security.api.preprocessor.CommonPreprocessor;
import com.hivemq.extensions.enterprise.security.api.preprocessor.CommonPreprocessorInitInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.CommonPreprocessorProcessInput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.CommonPreprocessorProcessOutput;
import com.hivemq.extensions.enterprise.security.api.preprocessor.CommonPreprocessorShutdownInput;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * This example {@link CommonPreprocessor} merges internal and external retrieved roles for connecting clients.
 * This custom preprocessor is meant to be used as {@code <authorization-preprocessor>}.
 * <p>
 * The preprocessor performs the following computational steps:
 * <ol>
 *     <li>Calls {@code output.async()} to signal asynchronous processing.</li>
 *     <li>Reads the ESE variable {@code authorization-key} from the input.</li>
 *     <li>Sends a request to the configured endpoint with the {@code authorization-key} value as query parameter.</li>
 *     <li>Reads the ESE variable {@code authorization-role-key} from the ESE variables input.</li>
 *     <li>Merges the roles from the ESE variable {@code authorization-role-key} and the roles retrieved from the endpoint to a new list.</li>
 *     <li>Writes the merged roles back to the ESE variable {@code authorization-role-key} on the output.</li>
 *     <li>Calls {@code async.resume()} to signal the completion of the asynchronous processing.</li>
 * </ol>
 * An example {@code external-roles-config.xml} file that enables this preprocessor is provided in {@code src/test/resources}.
 *
 * @author Mario Schwede
 * @since 4.36.0
 */
public class ExternalRolesCommonPreprocessor implements CommonPreprocessor {

    private static final @NotNull Logger LOGGER = LoggerFactory.getLogger(ExternalRolesCommonPreprocessor.class);

    private final @NotNull HttpClient httpClient = HttpClient.newHttpClient();

    private @Nullable URI rolesEndpoint;

    @Override
    public void init(final @NotNull CommonPreprocessorInitInput input) {
        LOGGER.debug("INIT");

        rolesEndpoint = input.getCustomSettings().getFirst("rolesEndpoint").map(URI::create).orElseThrow();
        LOGGER.debug("ENDPOINT: {}", rolesEndpoint);
    }

    @Override
    public void process(
            final @NotNull CommonPreprocessorProcessInput input,
            final @NotNull CommonPreprocessorProcessOutput output) {
        LOGGER.debug("PROCESS");

        final Async<CommonPreprocessorProcessOutput> async = output.async();
        try {
            final URI requestUri = new URI( //
                    requireNonNull(rolesEndpoint).getScheme(),
                    rolesEndpoint.getAuthority(),
                    rolesEndpoint.getPath(),
                    "user=" + input.getEseVariablesInput().getAuthorizationKey().orElseThrow(),
                    rolesEndpoint.getFragment());
            LOGGER.debug("URI: {}", requestUri);

            final HttpRequest request = HttpRequest.newBuilder().timeout(Duration.ofSeconds(5)).uri(requestUri).build();

            // Consider caching the response.
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()) //
                    .thenApply(HttpResponse::body) //
                    .thenAccept(body -> {
                        if (body != null && !body.isEmpty()) {
                            final List<String> roles = new ArrayList<>();
                            roles.addAll(input.getEseVariablesInput().getAuthorizationRoleKey().orElse(List.of()));
                            roles.addAll(List.of(body.split(",")));

                            LOGGER.debug("ROLES: {}", roles);
                            output.getEseVariablesOutput().setAuthorizationRoleKey(roles);
                        }
                    }).exceptionally(throwable -> {
                        LOGGER.warn("REQUEST FAILED", throwable);
                        return null;
                    })
                    // Always call async.resume() when finished.
                    .thenRun(async::resume);
        } catch (final Exception e) {
            LOGGER.warn("PROCESS FAILED", e);
            // Always call async.resume() when finished.
            async.resume();
        }
    }

    @Override
    public void shutdown(final @NotNull CommonPreprocessorShutdownInput input) {
        LOGGER.debug("SHUTDOWN");
    }
}
