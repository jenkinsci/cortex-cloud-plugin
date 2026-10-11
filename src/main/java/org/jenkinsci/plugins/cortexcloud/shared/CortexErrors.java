package org.jenkinsci.plugins.cortexcloud.shared;

import hudson.Util;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.UnresolvedAddressException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLException;

/**
 * Utility for producing clear, human-readable error descriptions from exceptions
 * across network and CLI operations.
 */
public final class CortexErrors {

    private CortexErrors() {}

    /**
     * Walks the cause chain of a {@link Throwable} and returns a human-readable,
     * actionable reason. Never returns null or the string "null".
     *
     * @param t the throwable to describe (may be null)
     * @return a concise, non-null diagnostic string
     */
    public static String describe(Throwable t) {
        if (t == null) {
            return "unknown error";
        }

        List<Throwable> chain = new ArrayList<>();
        for (Throwable curr = t; curr != null && !chain.contains(curr); curr = curr.getCause()) {
            chain.add(curr);
        }

        // 1. UnresolvedAddressException / UnknownHostException
        for (Throwable curr : chain) {
            if (curr instanceof UnknownHostException || curr instanceof UnresolvedAddressException) {
                String host = Util.fixEmptyAndTrim(curr.getMessage());
                if (host != null && !"null".equalsIgnoreCase(host)) {
                    return "could not resolve host " + host;
                }
                return "could not resolve host";
            }
        }

        // 2. ConnectException
        for (Throwable curr : chain) {
            if (curr instanceof ConnectException) {
                return "connection refused or unreachable";
            }
        }

        // 3. HttpTimeoutException / SocketTimeoutException
        for (Throwable curr : chain) {
            if (curr instanceof HttpTimeoutException || curr instanceof SocketTimeoutException) {
                return "timed out";
            }
        }

        // 4. SSLException
        for (Throwable curr : chain) {
            if (curr instanceof SSLException) {
                String msg = Util.fixEmptyAndTrim(curr.getMessage());
                if (msg == null || "null".equalsIgnoreCase(msg)) {
                    if (curr.getCause() != null) {
                        msg = Util.fixEmptyAndTrim(curr.getCause().getMessage());
                    }
                }
                if (msg != null && !"null".equalsIgnoreCase(msg)) {
                    return "TLS/SSL handshake failed (" + msg + ")";
                }
                return "TLS/SSL handshake failed";
            }
        }

        // 5. Anything else: first non-blank message in the chain, or simple class name
        for (Throwable curr : chain) {
            String msg = Util.fixEmptyAndTrim(curr.getMessage());
            if (msg != null && !"null".equalsIgnoreCase(msg)) {
                return msg;
            }
        }

        return t.getClass().getSimpleName();
    }
}
