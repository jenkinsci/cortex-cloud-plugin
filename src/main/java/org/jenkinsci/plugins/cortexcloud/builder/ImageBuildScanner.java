package org.jenkinsci.plugins.cortexcloud.builder;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import java.io.IOException;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.cortexcloud.global.Config;
import org.jenkinsci.plugins.cortexcloud.publisher.ScanResultAction;
import org.jenkinsci.plugins.cortexcloud.scanner.ImageScanner;
import org.jenkinsci.plugins.cortexcloud.scanner.ScanOutcome;
import org.jenkinsci.plugins.cortexcloud.shared.CortexErrors;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;
import org.jenkinsci.plugins.cortexcloud.shared.Severity;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

/**
 * Build step that scans a container image with the Cortex CLI.
 *
 * This is the Cortex replacement for the legacy prismaCloudScanImage step. It
 * works identically in freestyle jobs (added as a Build Step) and in Pipeline
 * via its @Symbol:
 *
 *     cortexScanImage image: 'myrepo/app:1.2.3'
 *
 * Pass/fail gating is driven by the CLI exit code (0 = pass, 1 = policy fail,
 * other = error); when isFailBuildOnPolicyViolation() is enabled (the default) a
 * policy fail or error aborts the build. Either way a ScanResultAction is
 * attached so the findings are visible on the build page.
 */
public class ImageBuildScanner extends AbstractBuildScanner {

    /** Image reference to scan, e.g. myrepo/app:1.2.3. Supports env-var expansion. */
    private final String image;

    /** Optional Docker daemon socket (maps to --docker-host). */
    private String dockerHost;

    /** Optional friendly name for the scan (maps to --name); defaults to the image ref. */
    private String scanName;

    /**
     * Optional scan source (maps to --source). Lets the tenant scope source-based
     * policies to Jenkins CI scans. Supports env-var expansion. Unset by default,
     * preserving the CLI's default behaviour.
     */
    private String source;

    /**
     * Optional upload mode (maps to --upload-mode). Controls how much scan data is
     * uploaded to and retained by the tenant. Unset by default, deferring to the
     * CLI default. Free text so it tracks whatever values the current CLI accepts.
     */
    private String uploadMode;

    /**
     * Plugin-side severity threshold for gating (NONE, LOW, MEDIUM, HIGH, CRITICAL).
     * When set above NONE, the build fails if any parsed vulnerability is at or
     * above this severity - independent of the CLI exit code. Defaults to NONE
     * (exit-code-only gating, matching the legacy plugin).
     */
    private Severity severityThreshold = Severity.NONE;

    // Fields in config.jelly must match the parameter names in this constructor.
    @DataBoundConstructor
    public ImageBuildScanner(String image) {
        super();
        this.image = image;
    }

    public String getImage() {
        return image;
    }

    public String getDockerHost() {
        return dockerHost;
    }

    @DataBoundSetter
    public void setDockerHost(String dockerHost) {
        this.dockerHost = dockerHost;
    }

    public String getScanName() {
        return scanName;
    }

    @DataBoundSetter
    public void setScanName(String scanName) {
        this.scanName = scanName;
    }

    public String getSource() {
        return source;
    }

    @DataBoundSetter
    public void setSource(String source) {
        this.source = source;
    }

    public String getUploadMode() {
        return uploadMode;
    }

    @DataBoundSetter
    public void setUploadMode(String uploadMode) {
        this.uploadMode = uploadMode;
    }

    public Severity getSeverityThreshold() {
        return severityThreshold == null ? Severity.NONE : severityThreshold;
    }

    @DataBoundSetter
    public void setSeverityThreshold(Severity severityThreshold) {
        this.severityThreshold = severityThreshold;
    }

    /** @return the configured threshold, defaulting to Severity.NONE. */
    Severity resolveThreshold() {
        return getSeverityThreshold();
    }

    @Override
    public void perform(
            @NonNull Run<?, ?> run,
            @NonNull FilePath workspace,
            @NonNull hudson.EnvVars env,
            @NonNull Launcher launcher,
            @NonNull TaskListener listener)
            throws InterruptedException, IOException {

        if (Util.fixEmptyAndTrim(image) == null) {
            abort("Cortex: image name is required");
        }

        Config config = Config.get();
        if (config == null) {
            abort("Cortex: global configuration is not available");
        }

        String resolvedImage = resolveEnvs(image, run, listener);
        String resolvedDockerHost = resolveEnvs(dockerHost, run, listener);
        String resolvedScanName = resolveEnvs(scanName, run, listener);
        String resolvedSource = resolveEnvs(source, run, listener);
        String resolvedUploadMode = resolveEnvs(uploadMode, run, listener);

        // CI correlation metadata from the build environment.
        String pipelineId = env.get("JOB_NAME");
        String buildId = env.get("BUILD_NUMBER");

        ImageScanner scanner = new ImageScanner(
                run,
                workspace,
                launcher,
                listener,
                config,
                resolvedImage,
                resolvedDockerHost,
                resolvedScanName,
                pipelineId,
                buildId,
                timeoutSecondsOrNull(),
                resolvedSource,
                resolvedUploadMode);

        ScanOutcome outcome;
        try {
            outcome = scanner.run();
        } catch (AbortException | InterruptedException e) {
            throw e;
        } catch (IOException e) {
            if (config.isDebug()) {
                e.printStackTrace(listener.getLogger());
            }
            String message = Util.fixEmptyAndTrim(e.getMessage());
            if (message == null || "null".equalsIgnoreCase(message)) {
                message = CortexErrors.describe(e);
            }
            throw new AbortException("Cortex: scan of image " + resolvedImage + " failed: " + message);
        }

        // 1) Tenant/CLI exit-code verdict (legacy behaviour).
        boolean exitPassed = outcome.isPass();

        // 2) Plugin-side severity threshold. The CLI (v0.31.0) returns exit 0 even
        //    for Critical CVEs, so this lets a pipeline block on findings
        //    regardless of tenant policy.
        Severity threshold = resolveThreshold();
        String breachMessage = evaluateThresholdBreach(outcome.getResult(), threshold, resolvedImage, listener);
        boolean thresholdBreached = breachMessage != null;

        boolean passed = exitPassed && !thresholdBreached;

        run.addAction(new ScanResultAction(
                resolvedImage, outcome.getExitCode(), passed, outcome.getResult(), outcome.getRawOutput()));

        // A severity-threshold breach reflects an explicit user intent ("fail if
        // findings reach severity X") and must fail the build independently of the
        // failBuildOnPolicyViolation checkbox, which only governs the CLI/tenant
        // exit-code verdict.
        if (thresholdBreached) {
            throw new AbortException(breachMessage);
        }

        if (!passed && isFailBuildOnPolicyViolation()) {
            if (outcome.isPolicyFailure()) {
                throw new AbortException(
                        "Cortex: image " + resolvedImage + " failed the tenant policy (CLI exit code 1)");
            }
            throw new AbortException("Cortex: scan of image " + resolvedImage + " errored (CLI exit code "
                    + outcome.getExitCode() + ")");
        }
    }

    /**
     * Applies the configured severity threshold to the parsed findings.
     *
     * <p>Both vulnerability findings and compliance findings (malware / secrets)
     * are evaluated against the same threshold. When the threshold is set but no
     * machine-readable findings could be parsed, the build fails closed (unless
     * {@link #isFailOnUnparseableResults()} has been disabled), so a critically
     * vulnerable image cannot pass green just because the CLI output could not be
     * understood.
     *
     * <p>Package-private so it can be unit-tested without a Jenkins harness.
     *
     * @return an abort message describing the breach, or null when the threshold
     * is disabled or nothing meets the threshold.
     */
    String evaluateThresholdBreach(CortexScanResult result, Severity threshold, String image, TaskListener listener) {
        if (threshold == null || threshold == Severity.NONE) {
            return null;
        }
        if (result == null) {
            // Fail closed: a threshold was requested but we have no findings to
            // evaluate it against. Treating this as "no breach" would let a
            // critically vulnerable image pass on a green build (see finding 01).
            if (isFailOnUnparseableResults()) {
                return "Cortex: severity threshold '" + threshold + "' is configured, but the CLI produced no "
                        + "machine-readable findings, so the threshold could not be evaluated. Failing closed. "
                        + "(Set failOnUnparseableResults=false to restore exit-code-only gating.)";
            }
            listener.getLogger()
                    .println("[Cortex] Severity threshold '" + threshold
                            + "' set, but no machine-readable findings were parsed and "
                            + "failOnUnparseableResults is disabled; gating falls back to the CLI exit code");
            return null;
        }

        int critical = result.countBySeverity("critical");
        int high = result.countBySeverity("high");
        int medium = result.countBySeverity("medium");
        int low = result.countBySeverity("low");

        listener.getLogger()
                .println("[Cortex] Findings by severity — Critical: " + critical
                        + ", High: " + high + ", Medium: " + medium + ", Low: " + low
                        + " (threshold: " + threshold + ", includes vulnerabilities + compliance)");

        int offending = 0;
        for (org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult.Result r : result.getResults()) {
            if (r.getEntityInfo() == null) {
                continue;
            }
            for (org.jenkinsci.plugins.cortexcloud.shared.Vulnerability v :
                    r.getEntityInfo().getVulnerabilities()) {
                if (Severity.fromString(v.getSeverity()).meetsOrExceeds(threshold)) {
                    offending++;
                }
            }
            // Compliance findings (malware / secrets) are gated against the same
            // threshold as CVEs (see finding 02); silently ignoring them would let
            // an image with malware or a leaked credential pass the build.
            for (org.jenkinsci.plugins.cortexcloud.shared.Vulnerability v :
                    r.getEntityInfo().getComplianceIssues()) {
                if (Severity.fromString(v.getSeverity()).meetsOrExceeds(threshold)) {
                    offending++;
                }
            }
        }

        if (offending > 0) {
            return "Cortex: image " + image + " has " + offending + " finding(s) at or above the " + threshold
                    + " severity threshold";
        }
        return null;
    }

    /**
     * Descriptor for ImageBuildScanner. Registers the step for freestyle and
     * Pipeline jobs and provides form validation.
     */
    @Extension
    @Symbol("cortexScanImage")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public DescriptorImpl() {
            load();
        }

        /**
         * Requires the caller to be allowed to configure the job (or, when there
         * is no job in context, to administer Jenkins) before returning any form
         * feedback, so validation endpoints cannot be probed without authority.
         */
        private static void checkConfigurePermission(Item item) {
            if (item == null) {
                Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            } else {
                item.checkPermission(Item.CONFIGURE);
            }
        }

        @POST
        public FormValidation doCheckDockerHost(@AncestorInPath Item item, @QueryParameter String value) {
            checkConfigurePermission(item);
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.ok();
            }
            String v = value.trim();
            if (!v.startsWith("unix://")
                    && !v.startsWith("tcp://")
                    && !v.startsWith("http://")
                    && !v.startsWith("https://")) {
                return FormValidation.warning(
                        "Expected a socket address, e.g. unix:///var/run/docker.sock or tcp://host:2376");
            }
            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @Override
        @NonNull
        public String getDisplayName() {
            return "Scan container image with Cortex Cloud";
        }
    }
}
