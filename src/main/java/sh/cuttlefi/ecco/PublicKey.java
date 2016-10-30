package sh.cuttlefi.ecco;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import sh.cuttlefi.ecco.exceptions.UnsupportedBaseException;

import java.math.BigInteger;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static sh.cuttlefi.ecco.impl.codec.BaseConvert.baseEncodedStringToByteArray;
import static sh.cuttlefi.ecco.impl.codec.BaseConvert.byteArrayToBaseEncodedString;
import static sh.cuttlefi.ecco.impl.Utils.*;

public class PublicKey {

    public final ECPoint point;
    public final ECDomainParameters curveParameters;
    private final ECDSASigner verifier = new ECDSASigner();

    /**
     * Verify if a point is valid for this curve.
     *
     * @param curveParameters The parameters of the elliptic curve to be used
     * @param point           An elliptic curve point
     * @return Whether this point was valid or not.
     */
    public static boolean isValidPoint(ECDomainParameters curveParameters, ECPoint point) {
        BigInteger x = point.getXCoord().toBigInteger();
        BigInteger y = point.getYCoord().toBigInteger();
        ECCurve ec = curveParameters.getCurve();
        BigInteger a = ec.getA().toBigInteger();
        BigInteger b = ec.getB().toBigInteger();
        BigInteger p = ec.getField().getCharacteristic();
        return x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p)
                .equals(y.multiply(y).mod(p));
    }

    /**
     * Construct a PublicKey given specified curve parameters and an elliptic curve point.
     *
     * @param curveParameters The parameters of the elliptic curve to use
     * @param point           The point to use as a public key on the elliptic curve
     * @throws SecurityException
     */
    public PublicKey(ECDomainParameters curveParameters, ECPoint point) throws SecurityException {
        if (point.getCurve() != curveParameters.getCurve())
            throw new SecurityException("Point is not on curve specified by curve parameters");
        if (!isValidPoint(curveParameters, point))
            throw new SecurityException("Cannot initialize an invalid elliptic curve point");
        this.point = point;
        this.curveParameters = curveParameters;
        verifier.init(false, new ECPublicKeyParameters(this.point, curveParameters));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PublicKey publicKey = (PublicKey) o;

        return point.equals(publicKey.point)
                && curveParameters.getCurve().equals(publicKey.curveParameters.getCurve())
                && curveParameters.getG().equals(publicKey.curveParameters.getG())
                && curveParameters.getN().equals(publicKey.curveParameters.getN())
                && curveParameters.getH().equals(publicKey.curveParameters.getH());

    }

    @Override
    public int hashCode() {
        int code = point.hashCode();
        code = 31 * code + curveParameters.getCurve().hashCode();
        code = 37 * code + curveParameters.getG().hashCode();
        code = 41 * code + curveParameters.getN().hashCode();
        code = 43 * code + curveParameters.getH().hashCode();
        return code;
    }

    /**
     * Recover an X9.62 encoded public key from an array of bytes
     *
     * @param curveParameters The parameters of the elliptic curve to be used
     * @param bytes           The X9.62 encoded public key
     * @return The public key corresponding to the input bytes
     * @throws SecurityException
     */
    public static PublicKey fromByteArray(
            ECDomainParameters curveParameters,
            byte[] bytes) throws SecurityException {
        return new PublicKey(curveParameters, curveParameters.getCurve().decodePoint(bytes));
    }

    /**
     * Recover an X9.62 encoded public key from a string encoding an array of bytes
     *
     * @param curveParameters The parameters of the elliptic curve to be used
     * @param string          The X9.62 encoded public key as a string encoding a byte array
     * @param base            The base of encoded string
     * @return The public key corresponding to the input string
     * @throws SecurityException In the event of an invalid key
     * @throws UnsupportedBaseException If the user is trying to convert from an unsupported base
     */
    public static PublicKey fromString(
            ECDomainParameters curveParameters,
            String string,
            int base) throws SecurityException, UnsupportedBaseException {
        return fromByteArray(curveParameters, baseEncodedStringToByteArray(string, base));
    }

    /**
     * Convert the elliptic curve point to a X9.62 compressed byte array encoding
     *
     * @return The compressed X9.62 byte array encoding of the curve point associated with the public key
     */
    public byte[] toByteArray() {
        return toByteArray(true);
    }

    /**
     * Convert the elliptic curve point to a X9.62 encoded byte array, with compression used as specified
     *
     * @param compressed Whether the resulting curve point is to be compressed when converted to a byte array
     * @return A X9.62 encoded byte array representing the curve point associated with the public key
     */
    public byte[] toByteArray(boolean compressed) {
        return point.getEncoded(compressed);
    }

    /**
     * Convert the elliptic curve point to a string representing a X9.62 compressed byte array encoding with the given base
     *
     * @param base Base to use when encoding
     * @return A string representing the compressed X9.62 byte array encoding
     * @throws UnsupportedBaseException
     */
    public String toString(int base) throws UnsupportedBaseException {
        return byteArrayToBaseEncodedString(toByteArray(), base);
    }

    /**
     * Convert the elliptic curve point to a string representing a X9.62 byte array encoding with the given base
     *
     * @param base       Base to use when encoding
     * @param compressed Whether to use compression or not when constructing the byte array
     * @return A string representing the X9.62 byte array encoding
     * @throws UnsupportedBaseException
     */
    public String toString(int base, boolean compressed) throws UnsupportedBaseException {
        return byteArrayToBaseEncodedString(toByteArray(compressed), base);
    }

    /**
     * Convert the elliptic curve point to a hexadecimal string encoding a X9.62 compressed byte array
     *
     * @return A hexadecimal string encoding a X9.62 compressed byte array
     */
    @Override
    public String toString() {
        return printHexBinary(toByteArray()).toLowerCase();
    }

    private static class TimeStampAndNonce {
        public final byte[] timeStampBytes;
        public final byte[] nonceBytes;

        public TimeStampAndNonce(long timeStamp, long nonce) {
            this.timeStampBytes = longToBytes(timeStamp);
            this.nonceBytes = longToBytes(nonce);
        }
    }

    private static class DeserializedSignature {
        public final BigInteger r;
        public final BigInteger s;
        public final byte recover;
        public final TimeStampAndNonce timeStampAndNonce;

        public DeserializedSignature(byte[] signature) {
            try (ASN1InputStream decoder = new ASN1InputStream(signature)) {
                DLSequence sequence = (DLSequence) decoder.readObject();
                int length = sequence.toArray().length;
                this.r = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
                this.s = ((ASN1Integer) sequence.getObjectAt(1)).getValue();
                this.recover = (length >= 3) ? (byte) ((ASN1Integer) sequence.getObjectAt(2)).getValue().intValue()
                        : 0;
                this.timeStampAndNonce = (length >= 5) ?
                        new TimeStampAndNonce(
                                ((ASN1Integer) sequence.getObjectAt(3)).getValue().longValue(),
                                ((ASN1Integer) sequence.getObjectAt(4)).getValue().longValue()) : null;
                // TODO: Test this sad path
                if (length == 4) {
                    throw new SecurityException("Signature cannot specify a time stamp without a nonce");
                }
                // TODO: Test this sad path
                if (length > 5) {
                    throw new SecurityException("Signature cannot have more than 5 entries");
                }
            } catch (Throwable e) {
                throw new SecurityException(e);
            }
        }
    }

    /**
     * Compute an elliptic curve point from a specified X coordinate given the parity of the Y coordinate
     *
     * @param curveParameters The parameters of the curve to use when specifying the X coordinate
     * @param yEven           Whether the Y coordinate is even or not
     * @param xCoordinate     The X coordinate of the curve point to be computed
     * @return The elliptic curve point given the specified curve parameters that has the appropriate X coordinate and Y coordinate
     * @throws SecurityException
     */
    private static ECPoint computePoint(ECDomainParameters curveParameters, boolean yEven, BigInteger xCoordinate)
            throws SecurityException {
        int bits = curveParameters.getN().bitLength();
        if (bits % 8 != 0) {
            throw new SecurityException("Curve does not have an even number of bytes");
        }
        int curveLength = bits / 8;
        byte[] raw = xCoordinate.toByteArray();
        byte[] input = new byte[curveLength + 1];
        if (raw.length > curveLength) {
            int zeros = countLeadingZeroBytes(raw);
            if (raw.length - zeros > curveLength) {
                throw new SecurityException("X Coordinate has more bytes than curve length");
            }
            System.arraycopy(raw, zeros, input, curveLength - (raw.length - zeros) + 1, raw.length - zeros);
        } else {
            System.arraycopy(raw, 0, input, curveLength - raw.length + 1, raw.length);
        }
        input[0] = (byte) (yEven ? 0x02 : 0x03);
        try {
            return curveParameters.getCurve().decodePoint(input);
        } catch (IllegalArgumentException e) {
            throw new SecurityException(e);
        }
    }

    // TODO: test when this is false

    /**
     * Recovers a {@code PublicKey}, given a hash, from an extended ECDSA signature that includes a recovery byte
     *
     * @param curveParameters The parameters of the curve to use when recovering a {@code PublicKey}
     * @param hash            The hash of the data that has been signed
     * @param signature       An extended ECDSA signature including a recovery byte
     * @return The public key recovered from the signature
     */
    private static PublicKey recoverPublicKeyFromHash(
            ECDomainParameters curveParameters,
            byte[] hash,
            byte[] signature) throws SecurityException {
        DeserializedSignature sig = new DeserializedSignature(signature);
        if (!(0x1B <= sig.recover && sig.recover <= 0x1E)) {
            throw new SecurityException("Invalid recovery byte");
        }
        boolean yEven = ((sig.recover - 0x1B) & 1) == 0;
        boolean isSecondKey = (((sig.recover - 0x1B) >> 1) & 1) == 1;
        BigInteger n = curveParameters.getN();
        ECPoint kp = computePoint(curveParameters, yEven, isSecondKey ? sig.r.add(n) : sig.r);
        BigInteger eInverse = n.subtract(new BigInteger(1, hash));
        BigInteger rInverse = sig.r.modInverse(n);
        ECPoint recoveredPointCandidate =
                ECAlgorithms
                        .sumOfTwoMultiplies(curveParameters.getG(), eInverse, kp, sig.s)
                        .multiply(rInverse)
                        .normalize();
        return new PublicKey(curveParameters, recoveredPointCandidate);
    }

    /**
     * Recovers a {@code PublicKey}, given a byte array of data, from an extended ECDSA signature of a hash of that data that includes a recovery byte
     *
     * @param curveParameters The parameters of the curve
     * @param data            The data that is to be hashed and signed
     * @param signature       An extended ECDSA signature including a recovery byte
     * @param hashDigest      The hashing digest to use to generate the hash that was signed
     * @return A recovered public key
     * @throws SecurityException
     */
    public static PublicKey recoverPublicKey(
            ECDomainParameters curveParameters,
            byte[] data,
            byte[] signature,
            GeneralDigest hashDigest) throws SecurityException {
        GeneralDigest freshHashDigest = freshDigestFromDigest(hashDigest);
        byte[] hash = new byte[freshHashDigest.getDigestSize()];
        DeserializedSignature sig = new DeserializedSignature(signature);
        if (sig.timeStampAndNonce != null) {
            freshHashDigest.update(sig.timeStampAndNonce.timeStampBytes, 0,
                    sig.timeStampAndNonce.timeStampBytes.length);
            freshHashDigest.update(sig.timeStampAndNonce.nonceBytes, 0,
                    sig.timeStampAndNonce.nonceBytes.length);
        }
        freshHashDigest.update(data, 0, data.length);
        freshHashDigest.doFinal(hash, 0);
        return recoverPublicKeyFromHash(curveParameters, hash, signature);
    }

    /**
     * Recovers a {@code PublicKey}, given a byte array of data, from an extended ECDSA signature of a SHA-256 hash of that data that includes a recovery byte
     *
     * @param curveParameters The parameters of the curve
     * @param data            The data that is to be SHA-256 hashed and signed
     * @param signature       An extended ECDSA signature including a recovery byte
     * @return A recovered public key
     * @throws SecurityException
     */
    public static PublicKey recoverPublicKey(
            ECDomainParameters curveParameters,
            byte[] data,
            byte[] signature) throws SecurityException {
        return recoverPublicKey(curveParameters, data, signature, new SHA256Digest());
    }

    public static PublicKey recoverPublicKeyFromSignedUTF8String(
            ECDomainParameters curveParameters,
            String string,
            byte[] signature,
            GeneralDigest hashDigest) throws SecurityException {
        return recoverPublicKey(curveParameters, stringToUTF8Bytes(string),signature, hashDigest);
    }

    public static PublicKey recoverPublicKeyFromSignedUTF8String(
            ECDomainParameters curveParameters,
            String string,
            byte[] signature) throws SecurityException {
        return recoverPublicKeyFromSignedUTF8String(curveParameters, string, signature, new SHA256Digest());
    }

    /**
     * Verify an ECDSA signature of a hash
     *
     * @param hash      A hashed value that has been signed
     * @param signature An ECDSA signature
     * @return Whether the signature is valid
     * @throws SecurityException
     */
    private boolean verifySignatureFromHash(byte[] hash, byte[] signature) throws SecurityException {
        DeserializedSignature sig = new DeserializedSignature(signature);
        if (sig.recover != 0) {
            return this.equals(recoverPublicKeyFromHash(this.curveParameters, hash, signature));
        }
        return verifier.verifySignature(hash, sig.r, sig.s);
    }

    /**
     * Verify an ECDSA Signature of a hash of specified input
     *
     * @param data       Data to be hashed
     * @param signature  Signature of the hashed data
     * @param hashDigest The hashing digest to use to generate the hash to check against the signature
     * @return Whether the signature is valid
     * @throws SecurityException
     */
    public boolean verifySignature(byte[] data, byte[] signature, GeneralDigest hashDigest)
            throws SecurityException {
        GeneralDigest freshHashDigest = freshDigestFromDigest(hashDigest);
        byte[] hash = new byte[hashDigest.getDigestSize()];
        DeserializedSignature sig = new DeserializedSignature(signature);
        if (sig.timeStampAndNonce != null) {
            freshHashDigest.update(sig.timeStampAndNonce.timeStampBytes, 0,
                    sig.timeStampAndNonce.timeStampBytes.length);
            freshHashDigest.update(sig.timeStampAndNonce.nonceBytes, 0,
                    sig.timeStampAndNonce.nonceBytes.length);
        }
        freshHashDigest.update(data, 0, data.length);
        freshHashDigest.doFinal(hash, 0);
        return verifySignatureFromHash(hash, signature);
    }

    /**
     * Verify an ECDSA Signature of a SHA-256 hash of specified input
     *
     * @param data      Data to be hashed
     * @param signature Signature of the hashed data
     * @return Whether the signature is valid
     * @throws SecurityException
     */
    public boolean verifySignature(byte[] data, byte[] signature)
            throws SecurityException {
        return verifySignature(data, signature, new SHA256Digest());
    }

    /**
     * Verify an ECDSA Signature of a hash of a UTF-8 encoded string
     *
     * @param string     The string to be hashed
     * @param signature  Signature of the hashed string
     * @param hashDigest The hashing digest to use to generate the hash to check against the signature
     * @return Whether the signature is valid
     * @throws SecurityException
     */
    public boolean verifySignedUTF8String(String string, byte[] signature, GeneralDigest hashDigest)
            throws SecurityException {
        return verifySignature(stringToUTF8Bytes(string), signature, hashDigest);
    }

    /**
     * Verify an ECDSA Signature of a SHA-256 hash of a UTF-8 encoded string
     *
     * @param string    The string to be hashed
     * @param signature Signature of the hashed string
     * @return Whether the signature is valid
     * @throws SecurityException
     */
    public boolean verifySignedUTF8String(String string, byte[] signature)
            throws SecurityException {
        return verifySignedUTF8String(string, signature, new SHA256Digest());
    }

}
