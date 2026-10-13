package org.jenkinsci.plugins.cortexcloud.scanner;

import java.util.LinkedList;
import java.util.List;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;

/**
 * Builds the "cortexcli image scan ..." argument list.
 *
 * This class is deliberately free of Jenkins APIs so the exact command line can
 * be unit-tested in isolation. The argument order and flags reflect the verified
 * Cortex CLI contract:
 *
 * <pre>{@code
 *     cortexcli image scan --archive --archive-format docker-archive \
 *         --name <name> --output-format json [--docker-host <sock>] \
 *         [--ci-pipeline-id <id>] [--ci-build-id <id>] [--timeout <s>] <target>
 * }</pre>
 *
 * - --archive is required when the target is a tar archive.
 * - The target (tarball path or image reference) is always the last argument.
 */
public class CortexCommandBuilder {

    private final String cliPath;
    private String name;
    private String target;
    private boolean archive = true;
    private String archiveFormat = CortexConstants.ARCHIVE_FORMAT_DOCKER;
    private String outputFormat = CortexConstants.OUTPUT_FORMAT_JSON;
    private String dockerHost;
    private String ciPipelineId;
    private String ciBuildId;
    private Integer timeoutSeconds;
    private String source;
    private String uploadMode;

    public CortexCommandBuilder(String cliPath) {
        this.cliPath = cliPath;
    }

    public CortexCommandBuilder name(String name) {
        this.name = name;
        return this;
    }

    /** Sets the scan target - a tarball path (with archive(true)) or an image reference. */
    public CortexCommandBuilder target(String target) {
        this.target = target;
        return this;
    }

    public CortexCommandBuilder archive(boolean archive) {
        this.archive = archive;
        return this;
    }

    public CortexCommandBuilder archiveFormat(String archiveFormat) {
        if (archiveFormat != null && !archiveFormat.isEmpty()) {
            this.archiveFormat = archiveFormat;
        }
        return this;
    }

    public CortexCommandBuilder outputFormat(String outputFormat) {
        if (outputFormat != null && !outputFormat.isEmpty()) {
            this.outputFormat = outputFormat;
        }
        return this;
    }

    public CortexCommandBuilder dockerHost(String dockerHost) {
        this.dockerHost = dockerHost;
        return this;
    }

    public CortexCommandBuilder ciPipelineId(String ciPipelineId) {
        this.ciPipelineId = ciPipelineId;
        return this;
    }

    public CortexCommandBuilder ciBuildId(String ciBuildId) {
        this.ciBuildId = ciBuildId;
        return this;
    }

    public CortexCommandBuilder timeoutSeconds(Integer timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        return this;
    }

    /** Sets the scan source (maps to --source); scopes source-based tenant policies to CI scans. */
    public CortexCommandBuilder source(String source) {
        this.source = source;
        return this;
    }

    /** Sets the upload mode (maps to --upload-mode); controls how much scan data is uploaded/retained. */
    public CortexCommandBuilder uploadMode(String uploadMode) {
        this.uploadMode = uploadMode;
        return this;
    }

    /**
     * @return the full argument list, beginning with the CLI executable path and
     * ending with the scan target.
     * @throws IllegalStateException if the target is not set.
     */
    public List<String> build() {
        if (target == null || target.isEmpty()) {
            throw new IllegalStateException("scan target (tarball path or image reference) is required");
        }

        LinkedList<String> cmd = new LinkedList<>();
        cmd.add(cliPath);
        cmd.add(CortexConstants.CMD_IMAGE);
        cmd.add(CortexConstants.CMD_SCAN);

        if (archive) {
            cmd.add(CortexConstants.FLAG_ARCHIVE);
            cmd.add(CortexConstants.FLAG_ARCHIVE_FORMAT);
            cmd.add(archiveFormat);
        }

        if (name != null && !name.isEmpty()) {
            cmd.add(CortexConstants.FLAG_NAME);
            cmd.add(name);
        }

        cmd.add(CortexConstants.FLAG_OUTPUT_FORMAT);
        cmd.add(outputFormat);

        if (dockerHost != null && !dockerHost.isEmpty()) {
            cmd.add(CortexConstants.FLAG_DOCKER_HOST);
            cmd.add(dockerHost);
        }

        if (ciPipelineId != null && !ciPipelineId.isEmpty()) {
            cmd.add(CortexConstants.FLAG_CI_PIPELINE_ID);
            cmd.add(ciPipelineId);
        }

        if (ciBuildId != null && !ciBuildId.isEmpty()) {
            cmd.add(CortexConstants.FLAG_CI_BUILD_ID);
            cmd.add(ciBuildId);
        }

        if (source != null && !source.isEmpty()) {
            cmd.add(CortexConstants.FLAG_SOURCE);
            cmd.add(source);
        }

        if (uploadMode != null && !uploadMode.isEmpty()) {
            cmd.add(CortexConstants.FLAG_UPLOAD_MODE);
            cmd.add(uploadMode);
        }

        if (timeoutSeconds != null && timeoutSeconds > 0) {
            cmd.add(CortexConstants.FLAG_TIMEOUT);
            cmd.add(String.valueOf(timeoutSeconds));
        }

        // Target is always the last positional argument.
        cmd.add(target);
        return cmd;
    }
}
