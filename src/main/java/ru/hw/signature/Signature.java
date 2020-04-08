package ru.hw.signature;

import lombok.val;
import org.apache.commons.lang3.tuple.ImmutablePair;

import java.math.BigInteger;
import java.util.Arrays;

import static ru.hw.signature.Utils.*;

public class Signature {
    private final RSA rsa;

    public Signature(RSA rsa) {
        this.rsa = rsa;
    }

    public static boolean verify(byte[] data, byte[] sign, ImmutablePair<BigInteger, BigInteger> privateKey) {
        val hash = BigInteger.valueOf(unsignedLong(Arrays.hashCode(data))).toByteArray();
        val deciphered = RSA.decipher(sign, privateKey.left, privateKey.right);

        return Arrays.equals(hash, deciphered);
    }

    public static byte[] sign(byte[] data, ImmutablePair<BigInteger, BigInteger> openKey) {
        val hash = BigInteger.valueOf(unsignedLong(Arrays.hashCode(data))).toByteArray();

        return RSA.encipher(hash, openKey.left, openKey.right);
    }

    public ImmutablePair<BigInteger, BigInteger> generatePublicKey() {
        return rsa.generatePublicKey();
    }

    public ImmutablePair<BigInteger, BigInteger> generatePrivateKey() {
        return rsa.generatePrivateKey();
    }
}
