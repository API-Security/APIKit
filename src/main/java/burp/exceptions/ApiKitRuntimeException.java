package burp.exceptions;

public class ApiKitRuntimeException extends RuntimeException {
    public ApiKitRuntimeException() {
        super();
    }

    public ApiKitRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public ApiKitRuntimeException(String message) {
        super(message);
    }

    public ApiKitRuntimeException(Throwable cause) {
        super(cause);
    }
}
