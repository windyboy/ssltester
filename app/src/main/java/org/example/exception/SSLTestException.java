package org.example.exception;

public class SSLTestException extends Exception {
    private final int exitCode;

    public SSLTestException(String message, int exitCode) {
        super(message);
        this.exitCode = exitCode;
    }

    public SSLTestException(String message, int exitCode, Throwable cause) {
        super(message, cause);
        this.exitCode = exitCode;
    }

    public int getExitCode() {
        return exitCode;
    }
} 