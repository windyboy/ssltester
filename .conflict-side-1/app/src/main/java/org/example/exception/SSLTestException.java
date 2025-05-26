package org.example.exception;

/**
 * Custom exception used within the SSL/TLS testing application.
 * This exception is thrown to signal specific error conditions encountered during
 * the testing process. It also carries an exit code that can be used by the
 * command-line tool to terminate with an appropriate status.
 */
public class SSLTestException extends Exception {
    /**
     * Default serial version UID.
     */
    private static final long serialVersionUID = 1L;

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
     * <p>Note that the detail message associated with {@code cause} is <i>not</i> automatically
     * incorporated in this exception's detail message.
     *
     * @param message  The detail message (which is saved for later retrieval by the {@link #getMessage()} method).
     * @param exitCode The exit code associated with this exception, intended for application termination.
     * @param cause    The cause (which is saved for later retrieval by the {@link #getCause()} method).
     *                 (A {@code null} value is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public SSLTestException(String message, int exitCode, Throwable cause) {
        super(message, cause);
        this.exitCode = exitCode;
    }

    /**
     * Returns the exit code associated with this error.
     * This code is intended for use as the application's exit status when
     * this exception is caught at the top level.
     *
     * @return The exit code.
     */
    public int getExitCode() {
        return exitCode;
    }
}