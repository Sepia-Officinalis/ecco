package sh.cuttlefi.ecco.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Test;

import org.junit.Assert;
import sh.cuttlefi.ecco.CurveParameters;
import sh.cuttlefi.ecco.PrivateKey;
import sh.cuttlefi.ecco.PublicKey;
import sh.cuttlefi.ecco.exceptions.UnsupportedBaseException;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static sh.cuttlefi.ecco.CurveParameters.secp256k1;
import static sh.cuttlefi.ecco.CurveParameters.secp256r1;
import static sh.cuttlefi.ecco.PrivateKey.getDefaultSignatureConfig;
import static sh.cuttlefi.ecco.impl.codec.BaseConvert.baseEncodedStringToByteArray;
import static sh.cuttlefi.ecco.impl.codec.BaseConvert.byteArrayToBaseEncodedString;

public class PrivateKeyTest {

    @Test
    public void testFromAndToString() throws Exception {
        Assert.assertEquals(
                "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                PrivateKey.fromString(
                secp256k1,
                "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                16).toString(16));
        Assert.assertEquals(PrivateKey.fromString(
                secp256k1,
                "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                16).toString(),
                "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c");
        Assert.assertEquals(PrivateKey.fromString(
                        secp256k1,
                        "01",
                        16).toString(),
                "01");
        Assert.assertEquals(PrivateKey.fromString(
                        secp256k1,
                        "01",
                        10).toString(10),
                "1");
    }

    @Test(expected = SecurityException.class)
    public void testFromStringEmptyStringThrows() throws Exception {
        PrivateKey.fromString(secp256k1, "", 16);
    }

    @Test(expected = SecurityException.class)
    public void testFromStringZeroStringThrows() throws Exception {
        PrivateKey.fromString(secp256k1, "00", 16);
    }

    @Test(expected = SecurityException.class)
    public void testFromStringVeryBigInputStringThrows() throws Exception {
        PrivateKey.fromString(secp256k1, "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08cc6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c", 16);
    }

    @Test(expected = UnsupportedBaseException.class)
    public void testFromStringUnsupportedBase() throws Exception {
        PrivateKey.fromString(secp256k1, "01", 1234);
    }

    @Test
    public void testGetPublicKey() throws Exception {
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).getPublicKey().toString(16),
                "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
        );
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).getPublicKey(),
                PublicKey.fromString(secp256k1,
                        "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1",
                        16));
        Assert.assertEquals(
                PrivateKey.fromString(
                        CurveParameters.getCurveParametersByName("secp256k1"),
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).getPublicKey(),
                PublicKey.fromString(secp256k1,
                        "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1",
                        16));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetTimeStampAndNonceSignatureConfigBuilderSadPath() throws Exception {
        new PrivateKey.SignatureConfigBuilder().setRecover(false).setTimeStampAndNonce(true);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetTimeStampAndNonceSignatureConfigSadPath() throws Exception {
        new PrivateKey.SignatureConfig(false, true, true, new SHA256Digest(), new SHA256Digest());
    }

    private static PrivateKey examplePrivateKey;

    static {
        try {
            examplePrivateKey = PrivateKey.fromString(secp256k1,
                    "AgC/Dji4Yyn4TqkJcuDd3ltenDh",
                    64);
        } catch (UnsupportedBaseException ignored) {
        }
    }

    @Test(expected = UnsupportedBaseException.class)
    public void testToStringUnsupportedBaseException() throws Exception {
        String out = examplePrivateKey.toString(12345);
        throw new RuntimeException(out);
    }

    @Test
    public void testEquality() throws Exception {
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16),
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16));
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16),
                PrivateKey.fromString(
                        secp256k1,
                        "000000c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16));
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16),
                PrivateKey.fromString(
                        CurveParameters.getCurveParametersByName("secp256k1"),
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16));
    }

    @Test
    public void testDeterministicSignatures() throws Exception {
        PrivateKey privateKey = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        String input = "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。";
        byte[] signatureBytes = privateKey.signUTF8String(input,
                new PrivateKey.SignatureConfigBuilder()
                .setRecover(false)
                .build());
        Assert.assertTrue(privateKey.getPublicKey().verifySignedUTF8String(input, signatureBytes));
        String signature = byteArrayToBaseEncodedString(signatureBytes, 16);
        Assert.assertEquals(signature, "3045022100a28224c02e60f4e0a345cfc1043de9be408301393eec9225ab849d6bed8b794302205d09d76f6ae27094c005883d41e7059bb14afb0d9b61f9c051dea384b5048834");
    }

    @Test
    public void testSignHash() throws Exception {
        PrivateKey privateKey = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        Method signHash = PrivateKey.class.getDeclaredMethod("signHash", byte[].class, PrivateKey.SignatureConfig.class);
        signHash.setAccessible(true);
        signHash.invoke(privateKey, new byte[secp256k1.getN().bitLength() / 8], getDefaultSignatureConfig());
    }

    @Test(expected = InvocationTargetException.class)
    public void testSignHashBigHashSadPath() throws Exception {
        PrivateKey privateKey = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        Method signHash = PrivateKey.class.getDeclaredMethod("signHash", byte[].class, PrivateKey.SignatureConfig.class);
        signHash.setAccessible(true);
        signHash.invoke(privateKey, new byte[512], getDefaultSignatureConfig());
    }

    @Test
    public void testHashCode() throws Exception {
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode(),
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode());
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode(),
                PrivateKey.fromString(
                        secp256k1,
                        "000000c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode());
        Assert.assertEquals(
                PrivateKey.fromString(
                        secp256k1,
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode(),
                PrivateKey.fromString(
                        CurveParameters.getCurveParametersByName("secp256k1"),
                        "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c",
                        16).hashCode());
    }

    @Test
    public void testDiffieHelman() throws Exception {
        PrivateKey privateKey1 = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        PrivateKey privateKey2 = PrivateKey.fromString(
                secp256k1,
                "0ffffffffffffffffffffffffffffffffff9252c7f55610b8d0859d8752235a9",
                16);
        Assert.assertArrayEquals(
                privateKey1.diffieHelmanSharedSecret(privateKey2.getPublicKey()),
                privateKey2.diffieHelmanSharedSecret(privateKey1.getPublicKey()));
    }

    @Test(expected = SecurityException.class)
    public void testDiffieHelmanSadPath() throws Exception {
        PrivateKey privateKey1 = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        PrivateKey privateKey2 = PrivateKey.fromString(
                secp256r1,
                "0ffffffffffffffffffffffffffffffffff9252c7f55610b8d0859d8752235a9",
                16);
        privateKey1.diffieHelmanSharedSecret(privateKey2.getPublicKey());
    }

    @Test
    public void testSignatureSadPath() throws Exception {
        PrivateKey privateKey1 = PrivateKey.fromString(
                secp256k1,
                "22c49372a7506d162e6551fca36eb59235a9252c7f55610b8d0859d8752235a9",
                16);
        PrivateKey privateKey2 = PrivateKey.fromString(
                secp256k1,
                "0ffffffffffffffffffffffffffffffffff9252c7f55610b8d0859d8752235a9",
                16);
        String message = "Moloch!";
        String data = byteArrayToBaseEncodedString(privateKey2.signUTF8String(message), 16);
        Assert.assertFalse(
                privateKey1.getPublicKey().verifySignedUTF8String(
                        message,
                        baseEncodedStringToByteArray(data, 16)));
    }



}