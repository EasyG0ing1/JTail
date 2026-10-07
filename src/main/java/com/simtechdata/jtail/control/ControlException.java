package com.simtechdata.jtail.control;

import java.io.IOException;

/** A failure talking to the control server (HTTP-level errors carry the status). */
public class ControlException extends IOException {
    private final int status;
    public ControlException(String message, int status) { super(message); this.status = status; }
    public ControlException(String message, Throwable cause) { super(message, cause); this.status = 0; }
    public int status() { return status; }
}
