package org.jenkinsci.plugins.cortexcloud.scanner;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.Node;
import hudson.model.Run;
import hudson.model.TaskListener;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.cortexcloud.api.CortexCliApi;
import org.jenkinsci.plugins.cortexcloud.global.Config;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;

/**
 * Abstract base for Cortex CLI scanners.
 *
 * This is the integration-layer analogue of the legacy plugin's Scanner: it
 * provisions the CLI, assembles the command, launches it on the build node via
 * the Jenkins Launcher, and turns the result into a ScanOutcome. The key
 * differences from the legacy implementation reflect the Cortex CLI contract:
 *
 * - Authentication is injected as environment variables (CORTEX_API_BASE_URL,
 *   CORTEX_API_KEY, CORTEX_API_KEY_ID) rather than a Base64 basic-auth blob.
 * - Gating is driven by the process exit code, not by re-deriving pass/fail from
 *   the JSON, so it works even on CLI versions that don't emit JSON.
 *
 * Subclasses build the concrete argument list (e.g. image scan) via buildCommand.
 */
public abstract class Scanner {

    protected final Run<?, ?> run;
    protected final FilePath workspace;
    protected final Launcher launcher;
    protected final TaskListener listener;
    protected final Config config;

    protected Scanner(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener, Config config) {
        this.run = run;
        this.workspace = workspace;
        this.launcher = launcher;
        this.listener = listener;
        this.config = config;
    }

    /**
     * Builds the concrete CLI argument list given the resolved CLI path.
     * The first element must be the CLI executable path.
     */
    protected abstract List<String> buildCommand(String cliPath) throws IOException, InterruptedException;

    /** Human-readable description of what is being scanned (for logs). */
    protected abstract String describeTarget();

    /** Timeout in seconds for the scan process, or null/non-positive for none. */
    protected abstract Integer getTimeoutSeconds();

    /**
     * Provisions the CLI, runs the scan, and returns its outcome.
     *
     * @throws IOException          on I/O failure
     * @throws InterruptedException if the build is aborted
     */
    public ScanOutcome run() throws IOException, InterruptedException {
        requireConfig();

        String cliPath = provisionCli();
        List<String> cmd = buildCommand(cliPath);
        EnvVars env = buildScanEnvironment();

        log("Scanning " + describeTarget());
        if (config.isDebug()) {
            // Secrets are passed via environment variables, never as command
            // arguments; the masker is applied as defense-in-depth.
            log("Command: "
                    + SecretMasker.forSecrets(config.getApiKeyPlainText())
                            .mask(String.join(" ", cmd))); // Check if this log shows the key
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exitCode = launch(cmd, env, out, err);

        String stdout = out.toString(StandardCharsets.UTF_8);
        String stderr = err.toString(StandardCharsets.UTF_8);

        // Defensively redact the API key from anything echoed to the build log,
        // in case a CLI version or error path prints it back.
        SecretMasker masker = SecretMasker.forSecrets(config.getApiKeyPlainText());
        emitCliOutput(masker, stdout, stderr, exitCode);

        CortexScanResult parsed = ScanOutputParser.parse(stdout);
        if (parsed == null && exitCode != CortexConstants.EXIT_ERROR) {
            log("No JSON results parsed from CLI output; gating will rely on the exit code");
        }

        log("Cortex CLI exited with code " + exitCode + " (" + verdictLabel(exitCode) + ")");

        // Store the masked output so the secret cannot leak via the build UI's
        // raw-output view either.
        return new ScanOutcome(exitCode, parsed, masker.mask(stdout));
    }

    /** Provisions (downloads or reuses) the cortexcli binary and returns its path on the agent. */
    private String provisionCli() throws IOException, InterruptedException {
        CortexCliApi api = new CortexCliApi(config.getApiBaseUrl(), config.getApiKeyPlainText(), config.getApiKeyId());
        CliProvisioner provisioner = new CliProvisioner(api, listener, config.isDebug());
        FilePath nodeRoot = nodeRootFor(workspace);
        return provisioner.resolve(nodeRoot, workspace, config.getCliPath());
    }

    /**
     * Builds the process environment, injecting the Cortex credentials as
     * environment variables (the CLI's authentication contract) on top of the
     * build's own environment.
     */
    private EnvVars buildScanEnvironment() throws IOException, InterruptedException {
        EnvVars env = run.getEnvironment(listener);
        env.put(CortexConstants.ENV_API_BASE_URL, Util.fixNull(config.getApiBaseUrl()));
        env.put(CortexConstants.ENV_API_KEY, Util.fixNull(config.getApiKeyPlainText()));
        env.put(CortexConstants.ENV_API_KEY_ID, Util.fixNull(config.getApiKeyId()));
        return env;
    }

    /**
     * Launches the CLI on the build node, capturing stdout/stderr, and honouring
     * the optional scan timeout. Returns the process exit code.
     */
    private int launch(List<String> cmd, EnvVars env, ByteArrayOutputStream out, ByteArrayOutputStream err)
            throws IOException, InterruptedException {
        Launcher.ProcStarter starter =
                launcher.launch().cmds(cmd).envs(env).pwd(workspace).stdout(out).stderr(err);

        Integer timeout = getTimeoutSeconds();
        if (timeout != null && timeout > 0) {
            return starter.start().joinWithTimeout(timeout, TimeUnit.SECONDS, listener);
        }
        return starter.join();
    }

    /**
     * Writes the (secret-masked) CLI output to the build log.
     *
     * Output handling mirrors the legacy Prisma Cloud Compute plugin:
     * - on the success path, verbose stdout is gated behind debug mode;
     * - on any non-zero exit (POLICY FAIL or ERROR), the CLI's own output is
     *   ALWAYS surfaced so the user can see why the scan failed without having to
     *   re-run with debug enabled.
     */
    private void emitCliOutput(SecretMasker masker, String stdout, String stderr, int exitCode) {
        boolean failed = exitCode != CortexConstants.EXIT_PASS;
        if ((config.isDebug() || failed) && !stdout.isEmpty()) {
            listener.getLogger().println(masker.mask(stdout));
        }
        if (!stderr.isEmpty()) {
            listener.getLogger().println(masker.mask(stderr));
        }
    }

    /** @return a human-readable label for a CLI exit code (PASS / POLICY FAIL / ERROR). */
    private static String verdictLabel(int exitCode) {
        if (exitCode == CortexConstants.EXIT_PASS) {
            return "PASS";
        }
        if (exitCode == CortexConstants.EXIT_FAIL) {
            return "POLICY FAIL";
        }
        return "ERROR";
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private void requireConfig() throws AbortException {
        if (config == null
                || Util.fixEmptyAndTrim(config.getApiBaseUrl()) == null
                || Util.fixEmptyAndTrim(config.getApiKeyPlainText()) == null
                || Util.fixEmptyAndTrim(config.getApiKeyId()) == null) {
            throw new AbortException("Cortex Cloud global configuration is incomplete. "
                    + "Set the API base URL, API key, and API key ID under Manage Jenkins -> System.");
        }
    }

    /** Best-effort node root for the agent owning workspace (for the CLI cache). */
    private static FilePath nodeRootFor(FilePath workspace) {
        try {
            hudson.model.Computer computer = workspace.toComputer();
            if (computer != null) {
                Node node = computer.getNode();
                if (node != null && node.getRootPath() != null) {
                    return node.getRootPath();
                }
            }
            Jenkins j = Jenkins.getInstanceOrNull();
            if (j != null && j.getRootPath() != null) {
                return j.getRootPath();
            }
        } catch (Exception ignored) {
            // fall back to workspace-based cache
        }
        return null;
    }

    protected void log(String msg) {
        listener.getLogger().println("[Cortex] " + msg);
    }
}
