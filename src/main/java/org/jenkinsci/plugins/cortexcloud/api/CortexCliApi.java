package org.jenkinsci.plugins.cortexcloud.api;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import hudson.ProxyConfiguration;
import hudson.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.jenkinsci.plugins.cortexcloud.shared.CortexConstants;
import org.jenkinsci.plugins.cortexcloud.shared.CortexErrors;

/**
 * Thin REST client for the Cortex tenant API.
 *
 * It is responsible for the one platform endpoint the plugin needs at build
 * time: the unified-CLI download-link lookup (CortexConstants.DOWNLOAD_LINK_PATH).
 * That endpoint both (a) proves the base URL and credentials are valid (used by
 * the global config's Test Connection) and (b) yields the signed URL + checksum
 * used to provision the cortexcli binary onto an agent.
 *
 * Authentication uses the same credentials the CLI consumes, sent as HTTP headers:
 * - {@code Authorization: <api key>}
 * - {@code x-xdr-auth-id: <api key id>}
 *
 * HTTP requests use {@link HttpClient} configured via
 * {@link ProxyConfiguration#newHttpClientBuilder()} to honour the Jenkins
 * global proxy configuration.
 */
public class CortexCliApi {

    private static final Gson GSON = new Gson();
    private static final int CONNECT_TIMEOUT_MS = 15_000;
    private static final int READ_TIMEOUT_MS = 30_000;

    /**
     * Upper bound on the response body we will read into memory. The expected
     * download-link JSON is a few hundred bytes; capping the read defends against
     * a misbehaving or hostile endpoint returning an unbounded body.
     */
    private static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private final String baseUrl;
    private final HttpClient httpClient;

    // Held in memory only for the lifetime of a single API call; this class is not
    // Serializable and is never persisted, so these values are not written to disk.
    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    private final String apiKey;

    @SuppressWarnings("lgtm[jenkins/plaintext-storage]")
    private final String apiKeyId;

    /**
     * @param baseUrl  tenant API base URL (trailing slash optional)
     * @param apiKey   API key (secret)
     * @param apiKeyId API key ID (maps to the x-xdr-auth-id header)
     */
    public CortexCliApi(String baseUrl, String apiKey, String apiKeyId) {
        this(baseUrl, apiKey, apiKeyId, defaultHttpClient());
    }

    CortexCliApi(String baseUrl, String apiKey, String apiKeyId, HttpClient httpClient) {
        this.baseUrl = stripTrailingSlash(baseUrl);
        this.apiKey = apiKey;
        this.apiKeyId = apiKeyId;
        this.httpClient = httpClient;
    }

    private static HttpClient defaultHttpClient() {
        return ProxyConfiguration.newHttpClientBuilder()
                .connectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Verifies connectivity and credentials by requesting a download link for
     * the current platform. A 2xx response with a usable signed URL means the
     * tenant is reachable and the credentials are accepted.
     *
     * @throws IOException if the request fails or the tenant rejects the credentials
     */
    public void testConnection() throws IOException {
        DownloadLink link = getDownloadLink(CortexConstants.OS_LINUX, CortexConstants.ARCH_AMD64);
        if (link == null || Util.fixEmptyAndTrim(link.signedUrl) == null) {
            throw new IOException("tenant did not return a download link (unexpected response)");
        }
    }

    /**
     * Requests a signed download link + checksum for the cortexcli binary
     * matching the given OS and architecture.
     *
     * @param os   one of CortexConstants.OS_LINUX, OS_DARWIN, OS_WINDOWS
     * @param arch one of CortexConstants.ARCH_AMD64, ARCH_ARM64
     * @return the parsed download link metadata
     * @throws IOException on transport error or non-2xx response
     */
    public DownloadLink getDownloadLink(String os, String arch) throws IOException {
        String urlString = baseUrl + CortexConstants.DOWNLOAD_LINK_PATH
                + "?" + CortexConstants.DOWNLOAD_PARAM_OS + "=" + enc(os)
                + "&" + CortexConstants.DOWNLOAD_PARAM_ARCH + "=" + enc(arch);

        final URI uri;
        try {
            uri = new URI(urlString);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URL: " + urlString, e);
        }

        HttpRequest req = ProxyConfiguration.newHttpRequestBuilder(uri)
                .GET()
                .timeout(Duration.ofMillis(READ_TIMEOUT_MS))
                .header(CortexConstants.HEADER_AUTHORIZATION, apiKey)
                .header(CortexConstants.HEADER_AUTH_ID, apiKeyId)
                .header("Accept", "application/json")
                .build();

        final HttpResponse<InputStream> resp;
        try {
            resp = httpClient.send(req, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(
                    "Interrupted while contacting Cortex API at " + CortexConstants.DOWNLOAD_LINK_PATH, e);
        } catch (IOException e) {
            throw new IOException(
                    "Could not reach the Cortex API at " + baseUrl + ": " + CortexErrors.describe(e)
                            + ". Check the API base URL and the Jenkins proxy settings.",
                    e);
        }

        int status = resp.statusCode();
        try (InputStream in = resp.body()) {
            if (status < 200 || status >= 300) {
                String body = readStream(in);
                throw new IOException("HTTP " + status + " from " + CortexConstants.DOWNLOAD_LINK_PATH
                        + (Util.fixEmptyAndTrim(body) == null ? "" : (": " + truncate(body))));
            }

            String body = readStream(in);
            DownloadLink link = GSON.fromJson(body, DownloadLink.class);
            if (link == null) {
                throw new IOException("empty/invalid JSON from " + CortexConstants.DOWNLOAD_LINK_PATH);
            }
            return link;
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static String stripTrailingSlash(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    private static String enc(String s) {
        return URLEncoder.encode(Util.fixNull(s), StandardCharsets.UTF_8);
    }

    /**
     * Reads a response body into a string, reading at most MAX_RESPONSE_BYTES so a
     * hostile or misbehaving endpoint cannot exhaust memory. Any bytes beyond
     * the cap are discarded.
     */
    private static String readStream(InputStream in) throws IOException {
        if (in == null) {
            return "";
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int total = 0;
        int n;
        while (total < MAX_RESPONSE_BYTES && (n = in.read(chunk)) != -1) {
            int remaining = MAX_RESPONSE_BYTES - total;
            int toWrite = Math.min(n, remaining);
            buffer.write(chunk, 0, toWrite);
            total += toWrite;
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static String truncate(String s) {
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }

    /**
     * Response body of CortexConstants.DOWNLOAD_LINK_PATH.
     * Shape (verified against a live tenant):
     * { "signed_url": "...", "checksum": "...", "file_name": "...", "expiration": ... }.
     *
     * Note: the tenant returns the checksum as an MD5 hex digest in practice (32
     * chars), not SHA-256. The verifier in CliProvisioner infers the algorithm
     * from the hex length, so it handles MD5, SHA-1, or SHA-256 transparently.
     */
    public static class DownloadLink implements Serializable {
        private static final long serialVersionUID = 1L;

        @SerializedName(
                value = "signed_url",
                alternate = {"signedUrl", "url"})
        public String signedUrl;

        @SerializedName(
                value = "checksum",
                alternate = {"md5", "md5Checksum", "sha256", "sha256Checksum"})
        public String checksum;

        @SerializedName(
                value = "file_name",
                alternate = {"fileName", "filename"})
        public String fileName;

        @SerializedName(
                value = "expiration",
                alternate = {"expires", "expiresAt"})
        public Long expiration;

        public String getSignedUrl() {
            return signedUrl;
        }

        public String getChecksum() {
            return checksum;
        }

        public String getFileName() {
            return fileName;
        }

        public Long getExpiration() {
            return expiration;
        }
    }
}
