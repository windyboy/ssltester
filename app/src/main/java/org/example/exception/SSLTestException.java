package org.example.exception;

/**
 * Custom exception class for the SSL Test application.
 * This exception is used to indicate specific error conditions encountered
 * during the SSL/TLS testing process, and it carries an exit code
 * that can be used by the command-line application.
 */
public class SSLTestException extends Exception {
    private final int exitCode;

    /**
     * Constructs a new SSLTestException with the specified detail message and exit code.
     *
     * @param message  The detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param exitCode The exit code associated with this exception, intended for application termination.
     */
    public SSLTestException(String message, int exitCode) {
        super(message);
        this.exitCode = exitCode;
    }

    /**
     * Constructs a new SSLTestException with the specified detail message, exit code, and cause.
     * <p>Note that the detail message associated with {@code cause} is
     * <i>not</i> automatically incorporated in this exception's detail message.
     *
     * @param message  The detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param exitCode The exit code associated with this exception.
     * @param cause    The cause (which is saved for later retrieval by the {@link #getCause()} method).
     *                 A {@code null} value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public SSLTestException(String message, int exitCode, Throwable cause) {
        super(message, cause);
        this.exitCode = exitCode;
    }

    /**
     * Gets the exit code associated with this exception.
     * This code is intended to be used as the application's exit status
     * when this exception leads to termination.
     *
     * @return The exit code.
     */
    public int getExitCode() {
        return exitCode;
    }
}