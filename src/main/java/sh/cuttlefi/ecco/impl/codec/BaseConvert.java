package sh.cuttlefi.ecco.impl.codec;


import sh.cuttlefi.ecco.exceptions.UnsupportedBaseException;

import static javax.xml.bind.DatatypeConverter.*;

/**
 * Utilities for converting various strings into byte arrays they encode for given bases
 */
public class BaseConvert {

    /**
     * Convert a string to a byte array it encodes
     *
     * @param string A string representing an array of bytes
     * @param base   The base the string is encoded with
     * @return The byte array the string represents
     * @throws UnsupportedBaseException Thrown if an unsupported base is handed as an argument
     */
    public static byte[] baseEncodedStringToByteArray(
            String string,
            int base) throws UnsupportedBaseException {
        switch (base) {
            case 16:
                return parseHexBinary(string);
            case 64:
                return parseBase64Binary(string);
            default:
                throw new UnsupportedBaseException("Unknown base given when trying to parse an encoded string to a byte array");
        }
    }

    /**
     * Convert a byte array into a encoded string
     *
     * @param bytes The bytes to encode as a string
     * @param base  The base of the encoding
     * @return An encoded string
     * @throws UnsupportedBaseException Thrown if an unsupported base is handed as an argument
     */
    public static String byteArrayToBaseEncodedString(
            byte[] bytes,
            int base) throws UnsupportedBaseException {
        switch (base) {
            case 16:
                return printHexBinary(bytes).toLowerCase();
            case 64:
                return printBase64Binary(bytes);
            default:
                throw new UnsupportedBaseException("Unknown base given when trying to write an string encoding a byte array");
        }
    }
}
