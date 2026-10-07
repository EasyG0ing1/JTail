package com.simtechdata.jtail;

/** Thrown when joining, using or leaving a tailnet fails. */
public class JTailException extends RuntimeException {
    public JTailException(String message) { super(message); }
    public JTailException(String message, Throwable cause) { super(message, cause); }
}
