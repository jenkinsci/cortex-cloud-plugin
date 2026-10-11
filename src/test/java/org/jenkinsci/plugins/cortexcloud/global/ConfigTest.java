package org.jenkinsci.plugins.cortexcloud.global;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessDeniedException3;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.Page;
import org.htmlunit.WebRequest;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * JenkinsRule tests for the global {@link Config}: setters persist, the API key
 * is stored as an encrypted {@link Secret}, the base URL is validated (SSRF
 * guard), and configuration/validation endpoints are permission-gated.
 */
@WithJenkins
class ConfigTest {

    @Test
    void persistsAndRoundTrips(JenkinsRule j) {
        Config config = Config.get();
        assertNotNull(config, "Config extension should be registered");

        config.setApiBaseUrl("https://api-tenant.xdr.us.paloaltonetworks.com");
        config.setApiKey(Secret.fromString("super-secret-key"));
        config.setApiKeyId("158");
        config.setCliPath("/opt/cortex/cortexcli");
        config.setDebug(true);

        // Re-fetch the singleton: values must be retained in memory.
        Config reloaded = Config.get();
        assertEquals("https://api-tenant.xdr.us.paloaltonetworks.com", reloaded.getApiBaseUrl());
        assertEquals("super-secret-key", reloaded.getApiKeyPlainText());
        assertEquals("158", reloaded.getApiKeyId());
        assertEquals("/opt/cortex/cortexcli", reloaded.getCliPath());
        assertTrue(reloaded.isDebug());
    }

    @Test
    void apiKeyIsStoredAsSecret(JenkinsRule j) {
        Config config = Config.get();
        config.setApiKey(Secret.fromString("another-key"));

        Secret secret = config.getApiKey();
        assertNotNull(secret);
        assertEquals("another-key", secret.getPlainText());
        // The encrypted form must not equal the plaintext.
        assertFalse(secret.getEncryptedValue().equals("another-key"));
    }

    @Test
    void apiKeyIsEncryptedInPersistedXml(JenkinsRule j) throws Exception {
        Config config = Config.get();
        config.setApiKey(Secret.fromString("plaintext-should-not-appear"));
        config.save();

        // Read the persisted global-config XML from JENKINS_HOME and confirm the
        // plaintext secret is absent (it is stored as an encrypted Secret).
        File xmlFile = new File(j.jenkins.getRootDir(), Config.class.getName() + ".xml");
        assertTrue(xmlFile.exists(), "global config XML should be persisted");
        String xml = new String(Files.readAllBytes(xmlFile.toPath()), StandardCharsets.UTF_8);
        assertFalse(xml.contains("plaintext-should-not-appear"), "config.xml must not contain the plaintext API key");
    }

    @Test
    void rejectsBlankRequiredFields(JenkinsRule j) {
        Config config = Config.get();
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiBaseUrl("").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiKey("").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiKeyId("").kind);
    }

    @Test
    void baseUrlValidationEnforcesHttpsAndPublicHost(JenkinsRule j) {
        Config config = Config.get();
        assertEquals(
                FormValidation.Kind.OK,
                config.doCheckApiBaseUrl("https://api-tenant.xdr.us.paloaltonetworks.com").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiBaseUrl("http://example.com").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiBaseUrl("https://localhost").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiBaseUrl("https://169.254.169.254").kind);
        assertEquals(FormValidation.Kind.ERROR, config.doCheckApiBaseUrl("not a url").kind);
    }

    @Test
    void nonAdminIsDeniedConfigAndTestConnection(JenkinsRule j) {
        // Only administrators may read/write global config; a plain authenticated
        // user must be denied both the validation and the test-connection endpoints.
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(
                new MockAuthorizationStrategy().grant(Jenkins.READ).everywhere().to("reader"));

        Config config = Config.get();
        User reader = User.getById("reader", true);
        try (ACLContext ignored = ACL.as2(reader.impersonate2())) {
            assertThrows(AccessDeniedException3.class, () -> config.doCheckApiBaseUrl("https://x.example.com"));
            assertThrows(
                    AccessDeniedException3.class, () -> config.doTestConnection("https://x.example.com", "k", "1"));
        }
    }

    @Test
    void testConnectionWithUnresolvableHostFailsCleanly(JenkinsRule j) {
        Config config = Config.get();
        FormValidation result = config.doTestConnection("https://nonexistent.invalid", "test-key", "123");
        assertEquals(FormValidation.Kind.ERROR, result.kind);
        assertTrue(result.getMessage().contains("Connection failed: Could not reach the Cortex API"));
        assertFalse(result.getMessage().contains("null"));
    }

    @Test
    void checkApiKeyRequiresPost(JenkinsRule j) throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        String checkUrl = "descriptorByName/" + Config.class.getName() + "/checkApiKey?value=test";

        // GET must be rejected with 405 Method Not Allowed
        FailingHttpStatusCodeException ex = assertThrows(FailingHttpStatusCodeException.class, () -> wc.goTo(checkUrl));
        assertEquals(405, ex.getStatusCode());

        // POST (with crumb handled automatically by WebClient) must succeed
        WebRequest postRequest = new WebRequest(new URL(j.getURL() + checkUrl), HttpMethod.POST);
        Page page = wc.getPage(postRequest);
        assertEquals(200, page.getWebResponse().getStatusCode());
    }
}
