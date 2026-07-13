package com.ghost.web;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Wraps a request so the body can be scored <em>before</em> the downstream handler reads it.
 *
 * <p>The constructor eagerly drains up to {@code capBytes} of the request body. If the body ends
 * within the cap it is fully buffered and {@link #bodyFullyMeasured()} is {@code true} with the
 * exact byte count in {@link #measuredBodyBytes()}. If the body exceeds the cap the wrapper stops
 * buffering, marks itself un-measured, and stitches the buffered prefix back in front of the
 * remaining live stream so the handler still receives every byte. Downstream reads (input stream
 * or reader) replay the captured body, so the wrapper is transparent to the handler.
 */
final class BufferedBodyRequestWrapper extends HttpServletRequestWrapper {

    private final boolean measured;
    private final long measuredBytes;
    private final InputStream replay;
    private ServletInputStream servletStream;
    private BufferedReader reader;

    BufferedBodyRequestWrapper(HttpServletRequest request, int capBytes) throws IOException {
        super(request);
        ServletInputStream source = request.getInputStream();
        byte[] head = source.readNBytes(Math.max(0, capBytes));
        int overflow = source.read();
        if (overflow == -1) {
            this.measured = true;
            this.measuredBytes = head.length;
            this.replay = new ByteArrayInputStream(head);
        } else {
            // Body exceeds the cap: keep streaming it through un-measured so the handler is intact,
            // but we cannot verify its length inline (documented limitation).
            this.measured = false;
            this.measuredBytes = -1;
            InputStream buffered = new SequenceInputStream(
                    new ByteArrayInputStream(head),
                    new ByteArrayInputStream(new byte[]{(byte) overflow}));
            this.replay = new SequenceInputStream(buffered, source);
        }
    }

    /** True when the whole body fit inside the cap and its exact size is known. */
    boolean bodyFullyMeasured() {
        return measured;
    }

    /** Exact number of body bytes actually streamed by the client; valid only when measured. */
    long measuredBodyBytes() {
        return measuredBytes;
    }

    @Override
    public ServletInputStream getInputStream() {
        if (servletStream == null) {
            servletStream = new ServletInputStream() {
                @Override public int read() throws IOException { return replay.read(); }
                @Override public int read(byte[] b, int off, int len) throws IOException { return replay.read(b, off, len); }
                @Override public boolean isFinished() {
                    try { return replay.available() == 0; } catch (IOException e) { return true; }
                }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener readListener) {
                    throw new UnsupportedOperationException("async reads not supported");
                }
            };
        }
        return servletStream;
    }

    @Override
    public BufferedReader getReader() {
        if (reader == null) {
            String enc = getCharacterEncoding();
            Charset cs = enc != null ? Charset.forName(enc) : StandardCharsets.UTF_8;
            reader = new BufferedReader(new InputStreamReader(getInputStream(), cs));
        }
        return reader;
    }
}
