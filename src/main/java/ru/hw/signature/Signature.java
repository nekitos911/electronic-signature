package ru.hw.signature;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.tuple.ImmutablePair;

import java.math.BigInteger;
import java.util.Arrays;

import static ru.hw.signature.Utils.unsignedInt;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Signature {
    public static boolean useStandardHashCode = true;

    public static boolean verify(byte[] data, byte[] sign, ImmutablePair<BigInteger, BigInteger> privateKey) {
        val hash = hash(data);
        val deciphered = RSA.decipher(sign, privateKey.left, privateKey.right);

        return Arrays.equals(hash, deciphered);
    }

    public static byte[] sign(byte[] data, ImmutablePair<BigInteger, BigInteger> openKey) {
        val hash = hash(data);
        return RSA.encipher(hash, openKey.left, openKey.right);
    }

    private static byte[] hash(byte[] data) {
        return useStandardHashCode ?
                BigInteger.valueOf(unsignedInt(Arrays.hashCode(data))).toByteArray() :
                new BigInteger(data).toByteArray();
    }
}
