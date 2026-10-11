package org.jenkinsci.plugins.cortexcloud.global;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.cortexcloud.api.CortexCliApi;
import org.jenkinsci.plugins.cortexcloud.shared.CortexErrors;
import org.jenkinsci.plugins.cortexcloud.shared.CortexUrlValidator;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * Global configuration for the Cortex Cloud Jenkins plugin.
 *
 * This mirrors the role of the legacy Prisma Cloud Compute plugin's Config (a
 * singleton GlobalConfiguration shown under Manage Jenkins -> System), but the
 * authentication model is different to match the verified Cortex CLI contract:
 *
 * - Legacy console address    -> Cortex API base URL (CORTEX_API_BASE_URL)
 * - Legacy username/password  -> Cortex API key (CORTEX_API_KEY) + API key ID
 *                                (CORTEX_API_KEY_ID)
 *
 * The API key is stored as a Secret so it is encrypted at rest and never
 * rendered back to the UI in plain text.
 */
@Extension
public final class Config extends GlobalConfiguration {

    /** Base URL of the tenant API, e.g. https://api-<tenant>.xdr.<region>.paloaltonetworks.com. */
    private String apiBaseUrl;

    /** API key (secret). Stored encrypted. */
    private Secret apiKey;

    /**
     * API key ID: the numeric identifier sent as the x-xdr-auth-id header.
     * It identifies the key but is not the secret; the secret is {@link #apiKey}, stored as a Secret.
     */
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    private String apiKeyId;

    /**
     * Optional absolute path to a pre-installed {@code cortexcli} binary on the
     * agent. When blank, the plugin downloads and caches the CLI automatically.
     */
    private String cliPath;

    /** When true, emit verbose CLI output to the build log. */
    private boolean debug;

    /** Convenience accessor for the singleton instance. */
    public static Config get() {
        return GlobalConfiguration.all().get(Config.class);
    }

    public Config() {
        // When Jenkins is restarted, load any saved configuration from disk.
        load();
    }

    private static String getString(Secret secret) {
        return secret != null ? secret.getPlainText() : null;
    }

    @CheckForNull
    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    /** @return the API key as a Secret (for binding the password field), or null. */
    @CheckForNull
    public Secret getApiKey() {
        return apiKey;
    }

    /** @return the plain-text API key for passing to the CLI/REST call, or null. */
    @CheckForNull
    public String getApiKeyPlainText() {
        return getString(apiKey);
    }

    @CheckForNull
    public String getApiKeyId() {
        return apiKeyId;
    }

    @CheckForNull
    public String getCliPath() {
        return cliPath;
    }

    public boolean isDebug() {
        return debug;
    }

    @DataBoundSetter
    public void setApiBaseUrl(String apiBaseUrl) {
        this.apiBaseUrl = Util.fixEmptyAndTrim(apiBaseUrl);
        save();
    }

    @DataBoundSetter
    public void setApiKey(Secret apiKey) {
        this.apiKey = apiKey;
        save();
    }

    @DataBoundSetter
    public void setApiKeyId(String apiKeyId) {
        this.apiKeyId = Util.fixEmptyAndTrim(apiKeyId);
        save();
    }

    @DataBoundSetter
    public void setCliPath(String cliPath) {
        this.cliPath = Util.fixEmptyAndTrim(cliPath);
        save();
    }

    @DataBoundSetter
    public void setDebug(boolean debug) {
        this.debug = debug;
        save();
    }

    // ---------------------------------------------------------------------
    // Form validation (on-the-fly, as the user types in the config page).
    // ---------------------------------------------------------------------

    @POST
    public FormValidation doCheckApiBaseUrl(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return validateApiBaseUrl(value);
    }

    /** Maps the base-URL validation outcome to a FormValidation; ok() when the URL is acceptable. */
    private static FormValidation validateApiBaseUrl(String value) {
        switch (CortexUrlValidator.validate(value)) {
            case BLANK:
                return FormValidation.error("Please set the Cortex API base URL");
            case MALFORMED:
                return FormValidation.error("The API base URL is not a valid URL");
            case NOT_HTTPS:
                return FormValidation.error("The API base URL must use HTTPS "
                        + "(https://api-<tenant>.xdr.<region>.paloaltonetworks.com)");
            case INTERNAL_HOST:
                return FormValidation.error("The API base URL must point at a public Cortex tenant, "
                        + "not a loopback, link-local, or private/internal address");
            case OK:
            default:
                return FormValidation.ok();
        }
    }

    @POST
    public FormValidation doCheckApiKey(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (Util.fixEmptyAndTrim(value) == null) {
            return FormValidation.error("Please set the API key");
        }
        return FormValidation.ok();
    }

    @POST
    public FormValidation doCheckApiKeyId(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (Util.fixEmptyAndTrim(value) == null) {
            return FormValidation.error("Please set the API key ID");
        }
        if (!value.trim().matches("\\d+")) {
            return FormValidation.warning("The API key ID is normally a small integer (e.g. 158)");
        }
        return FormValidation.ok();
    }

    /**
     * Validates connectivity to the tenant API using the supplied credentials.
     *
     * Annotated @POST and gated on Jenkins.ADMINISTER so the stored/entered
     * secret cannot be probed via a crafted GET request - this is the modern,
     * CSRF-safe equivalent of the legacy plugin's Test Connection.
     */
    @POST
    public FormValidation doTestConnection(
            @QueryParameter("apiBaseUrl") final String apiBaseUrl,
            @QueryParameter("apiKey") final String apiKey,
            @QueryParameter("apiKeyId") final String apiKeyId) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        FormValidation baseUrlValidation = validateApiBaseUrl(apiBaseUrl);
        if (baseUrlValidation.kind != FormValidation.Kind.OK) {
            return baseUrlValidation;
        }
        if (Util.fixEmptyAndTrim(apiKey) == null) {
            return FormValidation.error("API key is required");
        }
        if (Util.fixEmptyAndTrim(apiKeyId) == null) {
            return FormValidation.error("API key ID is required");
        }

        try {
            // A successful download-link lookup proves the base URL + credentials
            // are valid and the tenant is reachable, without running a full scan.
            CortexCliApi api = new CortexCliApi(apiBaseUrl, apiKey, apiKeyId);
            api.testConnection();
            return FormValidation.ok("Successfully connected to the Cortex tenant");
        } catch (Exception e) {
            String msg = Util.fixEmptyAndTrim(e.getMessage());
            if (msg == null || "null".equalsIgnoreCase(msg)) {
                msg = CortexErrors.describe(e);
            }
            return FormValidation.error("Connection failed: " + msg);
        }
    }
}
