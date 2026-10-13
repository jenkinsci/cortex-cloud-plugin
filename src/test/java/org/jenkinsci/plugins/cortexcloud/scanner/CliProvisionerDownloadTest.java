package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.FilePath;
import java.io.File;
import java.io.IOException;
import java.util.Locale;
import org.jenkinsci.plugins.cortexcloud.api.CortexCliApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests the fail-closed guarantees of {@link CliProvisioner#resolve} on the
 * download path, using a stub {@link CortexCliApi} so no real network call is
 * made.
 *
 * <p>These cover the two security controls that must never be bypassed before a
 * binary is executed: the download link must use HTTPS, and the tenant must
 * supply a usable, integrity-verifiable checksum. Both failures must abort with
 * no executable produced.</p>
 */
class CliProvisionerDownloadTest {

    /** The cached binary name the provisioner uses on the platform running the test. */
    private static final String BINARY_NAME =
            System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")
                    ? "cortexcli.exe"
                    : "cortexcli";

    /** A {@link CortexCliApi} that returns a canned download link without any I/O. */
    private static final class StubApi extends CortexCliApi {
        private final String signedUrl;
        private final String checksum;

        StubApi(String signedUrl, String checksum) {
            super("https://api-tenant.xdr.us.paloaltonetworks.com", "key", "1");
            this.signedUrl = signedUrl;
            this.checksum = checksum;
        }

        @Override
        public DownloadLink getDownloadLink(String os, String arch) {
            DownloadLink link = new DownloadLink();
            link.signedUrl = signedUrl;
            link.checksum = checksum;
            link.fileName = "cortexcli";
            return link;
        }
    }

    private static CliProvisioner provisionerFor(CortexCliApi api) {
        // Debug on, no TaskListener needed (CliProvisioner logs only when listener != null).
        return new CliProvisioner(api, null, true);
    }

    @Test
    void rejectsNonHttpsSignedUrlAndProducesNoBinary(@TempDir File tmp) {
        FilePath root = new FilePath(tmp);
        FilePath workspace = root.child("workspace");
        CliProvisioner provisioner =
                provisionerFor(new StubApi("http://example.com/cortexcli", "e747cc5c94973f1288c7cf4c7b84a384"));

        IOException ex = assertThrows(IOException.class, () -> provisioner.resolve(root, workspace, null));
        assertTrue(ex.getMessage().toLowerCase().contains("https"), "should refuse a non-HTTPS download link");

        FilePath cached = root.child(CliProvisioner.CACHE_DIR).child(BINARY_NAME);
        assertNoExecutable(cached);
    }

    @Test
    void refusesWhenTenantProvidesNoChecksum(@TempDir File tmp) {
        FilePath root = new FilePath(tmp);
        FilePath workspace = root.child("workspace");
        CliProvisioner provisioner = provisionerFor(new StubApi("https://example.com/cortexcli", ""));

        IOException ex = assertThrows(IOException.class, () -> provisioner.resolve(root, workspace, null));
        assertTrue(ex.getMessage().toLowerCase().contains("checksum"), "should refuse when no checksum is provided");

        FilePath cached = root.child(CliProvisioner.CACHE_DIR).child(BINARY_NAME);
        assertNoExecutable(cached);
    }

    @Test
    void refusesChecksumWithUnrecognizedLength(@TempDir File tmp) {
        FilePath root = new FilePath(tmp);
        FilePath workspace = root.child("workspace");
        // "deadbeef" is 8 hex chars → not MD5/SHA-1/SHA-256.
        CliProvisioner provisioner = provisionerFor(new StubApi("https://example.com/cortexcli", "deadbeef"));

        IOException ex = assertThrows(IOException.class, () -> provisioner.resolve(root, workspace, null));
        assertTrue(
                ex.getMessage().toLowerCase().contains("unrecognized"),
                "should refuse a checksum whose length maps to no known algorithm");

        FilePath cached = root.child(CliProvisioner.CACHE_DIR).child(BINARY_NAME);
        assertNoExecutable(cached);
    }

    private static void assertNoExecutable(FilePath cached) {
        try {
            assertFalse(cached.exists(), "no CLI binary should be left on disk after a failed provision");
        } catch (IOException | InterruptedException e) {
            throw new AssertionError(e);
        }
    }
}
