package sh.cuttlefi.ecco.exceptions;

/**
 * An exception for reporting unsupported bases encountered when
 * marshalling/unmarshalling byte arrays from encoded strings.
 */
public class UnsupportedBaseException extends Exception {
    public UnsupportedBaseException(String message) {
        super(message);
    }
}