package ru.hw.signature;

import lombok.val;
import org.apache.commons.lang3.tuple.ImmutablePair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static java.math.BigInteger.ONE;

public class RSA {
    // 256 bits
    private static final int bitsLength = 1 << 8;
    private final static Random rnd = new SecureRandom();
    private BigInteger n;
    private BigInteger d;
    private BigInteger e;

    public RSA init(BigInteger p, BigInteger q, BigInteger e) {
        val fi = (p.subtract(ONE).multiply(q.subtract(ONE)));

        this.e = e == null ? BigInteger.probablePrime(fi.bitLength() - 1, rnd) : e;
        this.n = p.multiply(q);
        this.d = this.e.modInverse(fi); // d = e^-1 mod fi

        return this;
    }

    public RSA init() {
        val p = BigInteger.probablePrime(bitsLength, rnd);
        val q = BigInteger.probablePrime(bitsLength, rnd);

        return init(p, q, null);
    }

    public ImmutablePair<BigInteger, BigInteger> generatePublicKey() {
        if (e == null || n == null) init();
        return new ImmutablePair<>(e, n);
    }

    public ImmutablePair<BigInteger, BigInteger> generatePrivateKey() {
        if (e == null || n == null) init();
        return new ImmutablePair<>(d, n);
    }

    public static byte[] encipher(byte[] data, BigInteger e, BigInteger n) {
        return new BigInteger(data).modPow(e, n).toByteArray();
    }

    public  static byte[] decipher(byte[] data, BigInteger d, BigInteger n) {
        return new BigInteger(data).modPow(d, n).toByteArray();
    }
}
