package org.jenkinsci.plugins.cortexcloud.shared;

/**
 * Constants describing the confirmed Cortex CLI contract.
 *
 * All values here were verified empirically against a live tenant. They
 * intentionally supersede earlier documentation-based assumptions.
 */
public final class CortexConstants {

    private CortexConstants() {
        // utility class
    }

    // ---------------------------------------------------------------------
    // Authentication — passed to the CLI via environment variables, NOT flags.
    // ---------------------------------------------------------------------
    /** Base URL of the tenant API, e.g. {@code https://api-<tenant>.xdr.<region>.paloaltonetworks.com}. */
    public static final String ENV_API_BASE_URL = "CORTEX_API_BASE_URL";
    /** API key (secret). */
    public static final String ENV_API_KEY = "CORTEX_API_KEY";
    /** API key ID - a small integer (e.g. 158); maps to the x-xdr-auth-id header. */
    public static final String ENV_API_KEY_ID = "CORTEX_API_KEY_ID";

    // HTTP headers used by the platform REST API (for provisioning / connection test).
    public static final String HEADER_AUTH_ID = "x-xdr-auth-id";
    public static final String HEADER_AUTHORIZATION = "Authorization";

    // ---------------------------------------------------------------------
    // image scan command (CLI v0.31.0+).
    // ---------------------------------------------------------------------
    public static final String CMD_IMAGE = "image";
    public static final String CMD_SCAN = "scan";

    /** Required when the source is a tar archive; without it the CLI treats the path as an image reference. */
    public static final String FLAG_ARCHIVE = "--archive";
    /** docker-archive (default) | oci-archive. */
    public static final String FLAG_ARCHIVE_FORMAT = "--archive-format";
    /** human-readable (default) | json. */
    public static final String FLAG_OUTPUT_FORMAT = "--output-format";
    /** Name assigned to the scanned image. */
    public static final String FLAG_NAME = "--name";
    /** Docker daemon socket to connect to (note: NOT {@code --docker-address}). */
    public static final String FLAG_DOCKER_HOST = "--docker-host";
    /** CI pipeline identifier. */
    public static final String FLAG_CI_PIPELINE_ID = "--ci-pipeline-id";
    /** CI build identifier. */
    public static final String FLAG_CI_BUILD_ID = "--ci-build-id";
    /** Timeout in seconds (CLI default: 60). */
    public static final String FLAG_TIMEOUT = "--timeout";
    /** Scan source, used by the tenant to scope source-based policies to CI scans. */
    public static final String FLAG_SOURCE = "--source";
    /** Controls how much scan data is uploaded to / retained by the tenant. */
    public static final String FLAG_UPLOAD_MODE = "--upload-mode";

    public static final String ARCHIVE_FORMAT_DOCKER = "docker-archive";
    public static final String ARCHIVE_FORMAT_OCI = "oci-archive";
    public static final String OUTPUT_FORMAT_JSON = "json";
    public static final String OUTPUT_FORMAT_HUMAN = "human-readable";

    // ---------------------------------------------------------------------
    // Exit codes (observed).
    // ---------------------------------------------------------------------
    /** Scan completed and PASSED policy. */
    public static final int EXIT_PASS = 0;
    /** Scan completed but FAILED policy (documented; to be confirmed against a blocking image). */
    public static final int EXIT_FAIL = 1;
    /** Error (bad args, license/service unavailable, etc.). */
    public static final int EXIT_ERROR = 2;

    // ---------------------------------------------------------------------
    // Binary provisioning — official download-link endpoint on the tenant API.
    // Returns { checksum, expiration, file_name, signed_url }.
    // ---------------------------------------------------------------------
    public static final String DOWNLOAD_LINK_PATH = "/public_api/v1/unified-cli/releases/download-link";
    public static final String DOWNLOAD_PARAM_OS = "os";
    public static final String DOWNLOAD_PARAM_ARCH = "architecture";

    // os values
    public static final String OS_LINUX = "linux";
    public static final String OS_DARWIN = "darwin";
    public static final String OS_WINDOWS = "windows";
    // architecture values
    public static final String ARCH_AMD64 = "amd64";
    public static final String ARCH_ARM64 = "arm64";

    /** The downloaded binary is a static Go executable — no JRE/Java is required on the agent. */
    public static final String CLI_BINARY_NAME = "cortexcli";
}
