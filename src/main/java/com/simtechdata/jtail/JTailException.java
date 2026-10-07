package com.simtechdata.jtail;

/**
 * Thrown when joining a tailnet fails or when an operation on a {@link Tailnet} cannot be completed.
 *
 * <p>This is an unchecked exception. Its message describes the cause (for example a rejected auth key, an unreachable
 * control server, a join timeout, or interactive login being required). Network operations such as
 * {@link Tailnet#dial(String, int)} signal I/O problems with the standard {@code java.net} and {@code java.io}
 * exceptions instead.
 */
public class JTailException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message.
     *
     * @param message a description of the failure
     */
    public JTailException(String message) { super(message); }

    /**
     * Creates an exception with a message and an underlying cause.
     *
     * @param message a description of the failure
     * @param cause   the underlying exception
     */
    public JTailException(String message, Throwable cause) { super(message, cause); }
}
