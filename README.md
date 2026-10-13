# Cortex Cloud Plugin for Jenkins

## Overview

The **Cortex Cloud** plugin integrates [Palo Alto Networks Cortex Cloud](https://www.paloaltonetworks.com/cortex)
container-image scanning into your Jenkins pipelines. Add a build step to any Freestyle or
Pipeline job and the plugin will scan your Docker images against your Cortex Cloud tenant,
surface the findings on the build page, and optionally **fail the build** when a policy is
violated or when vulnerabilities meet a severity threshold you choose. This plugin replaces the
legacy Prisma Cloud Compute (twistcli) plugin, using the Cortex Cloud Unified CLI and API.

It provisions the Cortex Cloud CLI automatically on the build node, runs the scan, and reports
results back into Jenkins — giving your teams fast, in-pipeline feedback on image risk before
artifacts are promoted or deployed.

## Features

- **Container image scanning** as a build step for both **Freestyle** and **Pipeline** jobs
  (Pipeline symbol: `cortexScanImage`).
- **Secure global configuration** — the API key is stored encrypted as a Jenkins `Secret`,
  injected into the CLI as an environment variable, and masked in build logs.
- **Severity-threshold gating** — fail the build when findings reach a chosen severity
  (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`).
- **Policy-violation gating** — fail the build when the scan is rejected by tenant policy.
- **Per-build results view** — vulnerabilities, compliance issues, and pass/fail status are
  shown directly on the build page.
- **Automatic CLI provisioning** — the Cortex Cloud CLI is downloaded, checksum-verified, and
  cached on the build node, or you can point the plugin at a pre-installed binary.

## Prerequisites

Before you begin, make sure you have:

- A **Cortex Cloud tenant** with API credentials — an **API base URL**, **API key**, and
  **API key ID**.
- **Docker available on the build agent/node** that runs the scan, so the CLI can access the
  image being scanned.

## Getting started

### 1. Configure your Cortex Cloud connection

Configure the plugin globally under **Manage Jenkins → System → Cortex Cloud**:

| Field | Description |
| --- | --- |
| **API base URL** | Your tenant API URL, e.g. `https://api-<tenant>.xdr.<region>.paloaltonetworks.com`. Must be an HTTPS URL for a public tenant. |
| **API key** | Your Cortex Cloud API key. Stored encrypted as a Jenkins `Secret` and never rendered back in plain text. |
| **API key ID** | The numeric Cortex Cloud API key ID. |
| **CLI path** *(optional)* | Absolute path to a pre-installed `cortexcli` binary on the build node. Leave blank to have the plugin download and cache the CLI automatically. |
| **Debug** *(optional)* | Emit verbose CLI output to the build log. |

> **Where do I get these?** In your Cortex Cloud tenant, refer to the
> [Cortex Cloud documentation](https://docs-cortex.paloaltonetworks.com/) for the exact steps and the required role/permissions for your tenant.

Use the **Test Connection** button to verify the base URL and credentials before saving.

#### Proxy

- Calls from the controller to the Cortex API and CLI download use the Jenkins proxy settings
  (**Manage Jenkins → System → HTTP Proxy Configuration**).
- The Cortex CLI runs on the build agent and uses that agent's standard `HTTP_PROXY` /
  `HTTPS_PROXY` environment variables. Set them on the node, or with `withEnv` in Pipeline.

### 2. Add a scan to your job

**Freestyle jobs:**

1. In the job configuration, add a build step: **Scan container image with Cortex Cloud**.
2. Set the **image** to scan (for example `alpine:3.20` or `myrepo/app:${BUILD_NUMBER}`).
3. Optionally set the Docker host, scan name, timeout, severity threshold, and whether a policy
   violation should fail the build.

**Pipeline jobs** — use the `cortexScanImage` step (only `image` is required):

```groovy
// Minimal
cortexScanImage image: 'alpine:3.20'

// With options
cortexScanImage image: 'alpine:3.20',
                severityThreshold: 'HIGH',
                failBuildOnPolicyViolation: true,
                dockerHost: 'unix:///var/run/docker.sock',
                scanName: 'my-image',
                source: 'jenkins',
                uploadMode: 'all',
                timeout: 120
```

## How build results are determined

A scan succeeds only when **both** conditions are met:

1. **CLI exit code** — the scan is considered failed when the CLI reports a policy violation
   (exit code `1`) or an error (any other non-zero exit code).
2. **Severity threshold** — when `severityThreshold` is set above `NONE`, the build fails if any
   finding is at or above the selected severity, independently of the CLI exit code. This threshold
   applies to **both vulnerabilities and compliance findings (malware / secrets)**, so an image
   containing malware or a leaked credential at or above the threshold fails the build.

A severity-threshold breach always fails the build, regardless of the `failBuildOnPolicyViolation`
checkbox — setting a threshold is treated as an explicit request to gate on findings. When the
`failBuildOnPolicyViolation` gate fails (CLI exit code) and that option is enabled (the default),
the build is likewise aborted.

If a threshold is configured but the CLI produces no machine-readable findings to evaluate it
against (for example, an unexpected CLI output shape), the build **fails closed** so a vulnerable
image cannot pass on a green build. Uncheck `failOnUnparseableResults` to fall back to
exit-code-only gating in that case.

Either way, a **Cortex Cloud Scan** result is attached to the build so the findings and
pass/fail status are always visible on the build page.

## Configuration reference

### Build step (`cortexScanImage`)

| Option | Description | Default |
| --- | --- | --- |
| `image` | Image reference to scan (supports environment-variable expansion). **Required.** | — |
| `dockerHost` | Docker daemon socket to use (maps to the CLI `--docker-host`). | *(unset — CLI default)* |
| `scanName` | Friendly name for the scan (maps to the CLI `--name`). | *(image reference)* |
| `source` | Scan source reported to the tenant (maps to the CLI `--source`); lets source-scoped tenant policies apply to Jenkins scans. Supports environment-variable expansion. | *(unset — CLI default)* |
| `uploadMode` | Controls how much scan data is uploaded to and retained by the tenant (maps to the CLI `--upload-mode`). Supports environment-variable expansion. | *(unset — CLI default)* |
| `severityThreshold` | Fail the build when findings — **vulnerabilities or compliance (malware / secrets)** — reach this severity: `NONE`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. | `NONE` |
| `timeout` | Scan timeout in seconds; `0` or a negative value falls back to the CLI default. | `0` (CLI default) |
| `failBuildOnPolicyViolation` | Fail the build when the CLI exit-code gate fails. | `true` |
| `failOnUnparseableResults` | When a `severityThreshold` is set but no machine-readable findings can be parsed, fail the build (fail closed). Uncheck to fall back to exit-code-only gating. | `true` |

### Global configuration

| Option | Description | Default |
| --- | --- | --- |
| `apiBaseUrl` | Tenant API base URL (HTTPS). | — |
| `apiKey` | Cortex Cloud API key (stored encrypted). | — |
| `apiKeyId` | Numeric Cortex Cloud API key ID. | — |
| `cliPath` | Path to a pre-installed CLI binary; blank to auto-download. | *(unset — auto-download)* |
| `debug` | Verbose CLI output in the build log. | `false` |

## Security

The API key is stored as an encrypted Jenkins `Secret`, injected into the CLI process as an
environment variable (never as a command-line argument), and masked in build logs. The CLI is
downloaded over HTTPS and integrity-verified against a checksum before it is executed, and the
configurable API base URL is validated to reduce the risk of SSRF.

To report a suspected vulnerability, please follow the
[Jenkins security process](https://www.jenkins.io/security/) rather than opening a public issue.

## Building from source

This is a standard Maven Jenkins plugin. With JDK 17 (or newer, as supported by the Jenkins
parent POM):

```bash
mvn clean verify   # compile, run tests, and produce target/cortex-cloud.hpi
mvn hpi:run        # run a local Jenkins with the plugin loaded for manual testing
```

For general guidance on developing Jenkins plugins, see the
[Jenkins plugin development documentation](https://www.jenkins.io/doc/developer/plugin-development/).

## Changelog

Release notes are published on the
[GitHub Releases page](https://github.com/jenkinsci/cortex-cloud-plugin/releases).

## Contributing

Contributions are welcome! Please open an [issue](https://github.com/jenkinsci/cortex-cloud-plugin/issues)
or [pull request](https://github.com/jenkinsci/cortex-cloud-plugin/pulls), and follow the standard
[Jenkins plugin contribution guidelines](https://www.jenkins.io/doc/developer/).

## Support

- **Bugs & feature requests:** [open an issue](https://github.com/jenkinsci/cortex-cloud-plugin/issues) on GitHub.
- **Security issues:** report privately via the [Jenkins security process](https://www.jenkins.io/security/).
- **Cortex Cloud product help:** contact [Palo Alto Networks support](https://www.paloaltonetworks.com/cortex).

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for the full text.
