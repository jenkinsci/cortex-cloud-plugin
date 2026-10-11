package org.jenkinsci.plugins.cortexcloud.shared;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.net.http.HttpTimeoutException;
import java.nio.channels.UnresolvedAddressException;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.Test;

class CortexErrorsTest {

    @Test
    void describeNullReturnsUnknownError() {
        assertEquals("unknown error", CortexErrors.describe(null));
    }

    @Test
    void describeConnectExceptionWithNullMessageAndUnresolvedAddressCause() {
        ConnectException ce = new ConnectException(null);
        ce.initCause(new UnresolvedAddressException());

        String message = CortexErrors.describe(ce);
        assertThat(message, containsString("could not resolve host"));
        assertThat(message, not(containsString("null")));
    }

    @Test
    void describeUnknownHostExceptionWithHost() {
        UnknownHostException uhe = new UnknownHostException("nonexistent.invalid");
        assertEquals("could not resolve host nonexistent.invalid", CortexErrors.describe(uhe));
    }

    @Test
    void describeConnectExceptionWithoutCause() {
        ConnectException ce = new ConnectException("Connection refused");
        assertEquals("connection refused or unreachable", CortexErrors.describe(ce));
    }

    @Test
    void describeTimeouts() {
        SocketTimeoutException ste = new SocketTimeoutException("Read timed out");
        assertEquals("timed out", CortexErrors.describe(ste));

        HttpTimeoutException hte = new HttpTimeoutException("request timed out");
        assertEquals("timed out", CortexErrors.describe(hte));
    }

    @Test
    void describeSslException() {
        SSLException sslWithMsg = new SSLException("PKIX path building failed");
        assertEquals("TLS/SSL handshake failed (PKIX path building failed)", CortexErrors.describe(sslWithMsg));

        SSLException sslNullMsg = new SSLException((String) null);
        assertEquals("TLS/SSL handshake failed", CortexErrors.describe(sslNullMsg));
    }

    @Test
    void describeGenericExceptionWithMessage() {
        IOException ioe = new IOException("Disk quota exceeded");
        assertEquals("Disk quota exceeded", CortexErrors.describe(ioe));
    }

    @Test
    void describeGenericExceptionWithoutMessageReturnsClassName() {
        IOException ioe = new IOException((String) null);
        assertEquals("IOException", CortexErrors.describe(ioe));
    }

    @Test
    void describeNeverReturnsLiteralNullString() {
        Exception e = new Exception("null");
        assertEquals("Exception", CortexErrors.describe(e));
    }
}
