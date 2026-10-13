package org.jenkinsci.plugins.cortexcloud.scanner;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.List;
import org.jenkinsci.plugins.cortexcloud.shared.CortexScanResult;
import org.jenkinsci.plugins.cortexcloud.shared.Vulnerability;

/**
 * Parser for Cortex CLI "image scan --output-format json" output.
 *
 * The CLI (verified against v0.31.0 on a live tenant) emits:
 *
 *     {@code <SCAN_INTRO_START>{"imageName":...,"scanners":[...]}<SCAN_INTRO_END>}
 *     {"asset_name":"alpine:3.2","image_id":"sha256:...","analysis":[
 *        {"type":"Malware","distribution":{...},"findings":[]},
 *        {"type":"Secrets","distribution":{...},"findings":[]},
 *        {"type":"Vulnerability","distribution":{...},"findings":[ {XDM finding}, ... ]}
 *     ]}
 *
 * Each finding uses XDM-namespaced keys, with the interesting values nested under
 * xdm.finding.normalized_fields:
 *
 * - xdm.vulnerability.cve_id, .severity, .cvss_score
 * - xdm.vulnerability.status (e.g. "fixed in 1.33.2"), .cve_vendor_link,
 *   .fix_date, .publish_date
 * - xdm.software_package.id / .version
 *
 * Note: the distribution counts are unreliable (total was 0 even with 20
 * findings), so severity counts are derived from the findings themselves.
 *
 * The parser strips the intro block, isolates the main JSON object, and maps
 * findings onto the Vulnerability view model. It falls back gracefully (returns
 * null) when no parseable JSON is present, in which case gating relies on the CLI
 * exit code alone.
 */
public final class ScanOutputParser {

    static final String INTRO_START = "<SCAN_INTRO_START>";
    static final String INTRO_END = "<SCAN_INTRO_END>";

    /** Legacy data marker used by the twistcli-based plugin (still tolerated). */
    public static final String DATA_PREFIX = "=====DATA";

    private ScanOutputParser() {
        // utility
    }

    /**
     * @param output raw CLI stdout
     * @return a parsed CortexScanResult, or null if none could be extracted
     */
    public static CortexScanResult parse(String output) {
        if (output == null || output.isBlank()) {
            return null;
        }

        // 1) legacy =====DATA prefixed line
        String dataLine = extractDataPrefixedJson(output);
        if (dataLine != null) {
            CortexScanResult r = tryParseXdm(dataLine);
            if (r != null) {
                return r;
            }
        }

        // 2) strip the <SCAN_INTRO_*> preamble, then parse the main object.
        String body = stripIntro(output);
        String main = extractMainJsonObject(body);
        if (main != null) {
            CortexScanResult r = tryParseXdm(main);
            if (r != null) {
                return r;
            }
        }

        return null;
    }

    /**
     * Removes the {@code <SCAN_INTRO_START>...<SCAN_INTRO_END>} block (and anything before
     * it) so only the main result JSON remains.
     */
    static String stripIntro(String output) {
        int end = output.indexOf(INTRO_END);
        if (end >= 0) {
            return output.substring(end + INTRO_END.length());
        }
        return output;
    }

    private static CortexScanResult tryParseXdm(String json) {
        final JsonObject root;
        try {
            JsonElement el = JsonParser.parseString(json);
            if (!el.isJsonObject()) {
                return null;
            }
            root = el.getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException e) {
            return null;
        }

        if (!root.has("analysis")) {
            // Not the XDM shape we understand.
            return null;
        }

        String imageName = asString(root, "asset_name");
        String imageId = asString(root, "image_id");

        List<Vulnerability> vulns = new ArrayList<>();
        List<Vulnerability> compliance = new ArrayList<>();

        JsonElement analysisEl = root.get("analysis");
        if (analysisEl != null && analysisEl.isJsonArray()) {
            for (JsonElement aEl : analysisEl.getAsJsonArray()) {
                if (!aEl.isJsonObject()) {
                    continue;
                }
                JsonObject analysis = aEl.getAsJsonObject();
                String type = asString(analysis, "type");
                JsonElement findingsEl = analysis.get("findings");
                if (findingsEl == null || !findingsEl.isJsonArray()) {
                    continue;
                }
                boolean isVuln = "Vulnerability".equalsIgnoreCase(type);
                for (JsonElement fEl : findingsEl.getAsJsonArray()) {
                    if (!fEl.isJsonObject()) {
                        continue;
                    }
                    Vulnerability v = mapFinding(fEl.getAsJsonObject(), type);
                    if (v == null) {
                        continue;
                    }
                    if (isVuln) {
                        vulns.add(v);
                    } else {
                        compliance.add(v);
                    }
                }
            }
        }

        // Presence of a parseable analysis block is itself a successful parse,
        // even when there are zero findings (a clean image). Pass/fail is decided
        // downstream by the exit code and (optionally) severity thresholds.
        return CortexScanResult.fromFindings(imageName, imageId, vulns, compliance, "", true);
    }

    /**
     * Maps a single XDM finding object onto a Vulnerability. Reads the interesting
     * values from xdm.finding.normalized_fields.
     */
    static Vulnerability mapFinding(JsonObject finding, String analysisType) {
        JsonObject nf = finding.has("xdm.finding.normalized_fields")
                        && finding.get("xdm.finding.normalized_fields").isJsonObject()
                ? finding.getAsJsonObject("xdm.finding.normalized_fields")
                : new JsonObject();

        String cve = asString(nf, "xdm.vulnerability.cve_id");
        String severity = asString(nf, "xdm.vulnerability.severity");
        double cvss = asDouble(nf, "xdm.vulnerability.cvss_score");
        String status = asString(nf, "xdm.vulnerability.status");
        String link = asString(nf, "xdm.vulnerability.cve_vendor_link");
        long fixDate = asLong(nf, "xdm.vulnerability.fix_date");
        long published = asLong(nf, "xdm.vulnerability.publish_date");

        String pkgName = asString(nf, "xdm.software_package.id");
        String pkgVersion = asString(nf, "xdm.software_package.version");

        String description = asString(finding, "xdm.finding.description");

        Vulnerability v = Vulnerability.create()
                .cve(cve)
                .severity(severity)
                .cvss(cvss)
                .status(status)
                .link(link)
                .fixDate(fixDate)
                .published(published)
                .packageName(pkgName)
                .packageVersion(pkgVersion)
                .description(description);

        if ("Vulnerability".equalsIgnoreCase(analysisType)) {
            v.type("Vulnerability");
        } else {
            // Malware / Secrets / config findings are shown in the compliance table.
            v.type("Compliance");
            v.title(cve.isEmpty() ? analysisType : cve);
        }
        return v;
    }

    // ---------------------------------------------------------------------
    // JSON helpers (null-safe)
    // ---------------------------------------------------------------------

    private static String asString(JsonObject o, String key) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return "";
        }
        try {
            return o.get(key).getAsString();
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static double asDouble(JsonObject o, String key) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return 0.0;
        }
        try {
            return o.get(key).getAsDouble();
        } catch (RuntimeException e) {
            return 0.0;
        }
    }

    private static long asLong(JsonObject o, String key) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) {
            return 0L;
        }
        try {
            return o.get(key).getAsLong();
        } catch (RuntimeException e) {
            return 0L;
        }
    }

    private static String extractDataPrefixedJson(String output) {
        String[] lines = output.split("\\r?\\n");
        for (String line : lines) {
            if (line.startsWith(DATA_PREFIX)) {
                return line.substring(DATA_PREFIX.length()).trim();
            }
        }
        return null;
    }

    /**
     * Extracts the first top-level brace-balanced JSON object from arbitrary text,
     * ignoring braces that appear inside string literals.
     */
    static String extractMainJsonObject(String output) {
        int start = output.indexOf('{');
        if (start < 0) {
            return null;
        }
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = start; i < output.length(); i++) {
            char c = output.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return output.substring(start, i + 1);
                }
            }
        }
        return null;
    }
}
