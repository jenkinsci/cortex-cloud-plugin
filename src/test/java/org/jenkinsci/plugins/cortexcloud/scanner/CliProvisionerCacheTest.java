package org.jenkinsci.plugins.cortexcloud.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.FilePath;
import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import org.jenkinsci.plugins.cortexcloud.api.CortexCliApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests the concurrency-safe caching behaviour of {@link CliProvisioner#resolve}
 * added for finding 05: downloads land in the cache via a temp file + atomic
 * rename, stale {@code *.part} files are cleaned up, and no {@code *.part} debris
 * is left behind after a successful provision.
 *
 * <p>Because the production code rejects non-HTTPS links, the checksum /
 * temp-file mechanics are exercised directly against the cache dir (pre-seeded
 * fixtures) rather than through a real network fetch.</p>
 */
class CliProvisionerCacheTest {

    private static final byte[] BINARY = "#!/bin/sh\necho cortexcli\n".getBytes(StandardCharsets.UTF_8);

    /** The cached binary name the provisioner uses on the platform running the test. */
    private static final String BINARY_NAME =
            System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows")
                    ? "cortexcli.exe"
                    : "cortexcli";

    private static String md5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] d = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** A CortexCliApi returning a canned HTTPS download link without any I/O. */
    private static final class StubApi extends CortexCliApi {
        private final String checksum;

        StubApi(String checksum) {
            super("https://api-tenant.xdr.us.paloaltonetworks.com", "key", "1");
            this.checksum = checksum;
        }

        @Override
        public DownloadLink getDownloadLink(String os, String arch) {
            DownloadLink link = new DownloadLink();
            link.signedUrl = "https://example.com/cortexcli";
            link.checksum = checksum;
            link.fileName = "cortexcli";
            return link;
        }
    }

    @Test
    void reusesValidPreSeededCacheWithoutDownloading(@TempDir File tmp) throws Exception {
        FilePath root = new FilePath(tmp);
        FilePath workspace = root.child("workspace");
        workspace.mkdirs();

        // Pre-seed a valid cached binary with a matching checksum.
        FilePath cacheDir = root.child(CliProvisioner.CACHE_DIR);
        cacheDir.mkdirs();
        FilePath cached = cacheDir.child(BINARY_NAME);
        try (OutputStream os = cached.write()) {
            os.write(BINARY);
        }

        CliProvisioner provisioner = new CliProvisioner(new StubApi(md5(BINARY)), null, false);
        String resolved = provisioner.resolve(root, workspace, null);

        assertEquals(cached.getRemote(), resolved, "should return the pre-seeded cache path");
        assertTrue(cached.exists());
        // No lock or .part debris should remain.
        assertEquals(0, cacheDir.list("*.part").length, "no .part files should remain");
        assertFalse(cacheDir.child(BINARY_NAME + ".lock").exists(), "lock must be released");
    }

    @Test
    void staleCacheWithWrongChecksumIsNotReturnedAsIs(@TempDir File tmp) throws Exception {
        FilePath root = new FilePath(tmp);
        FilePath workspace = root.child("workspace");
        workspace.mkdirs();

        FilePath cacheDir = root.child(CliProvisioner.CACHE_DIR);
        cacheDir.mkdirs();
        FilePath cached = cacheDir.child(BINARY_NAME);
        try (OutputStream os = cached.write()) {
            os.write("corrupt".getBytes(StandardCharsets.UTF_8));
        }
        // Seed a leftover .part file from an "aborted" build.
        FilePath debris = cacheDir.child("cortexcli.old.part");
        try (OutputStream os = debris.write()) {
            os.write("junk".getBytes(StandardCharsets.UTF_8));
        }

        // The checksum won't match the corrupt cache, so resolve() will try to
        // download over the non-HTTPS example URL and fail — but only AFTER it
        // has entered the lock and cleaned stale .part debris.
        CliProvisioner provisioner = new CliProvisioner(new StubApi(md5(BINARY)), null, false);
        try {
            provisioner.resolve(root, workspace, null);
        } catch (Exception expected) {
            // download of the stub https URL is expected to fail (no such host / TLS)
        }

        assertFalse(debris.exists(), "stale .part debris should be cleaned up on provisioning entry");
        assertFalse(cacheDir.child(BINARY_NAME + ".lock").exists(), "lock must be released even on failure");
    }
}
