package ru.hw.signature;

import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TestSign {
    @RepeatedTest(20)
    public void testRSAWithGeneratedPAndQ() {
        val expectedText = RandomStringUtils.randomAscii(32).getBytes();
        val rsa = new RSA();
        val openPair = rsa.generatePublicKey();
        val privatePair = rsa.generatePrivateKey();
        val enc = RSA.encipher(expectedText, openPair.left, openPair.right);
        val dec = RSA.decipher(enc, privatePair.left, privatePair.right);

        Assertions.assertArrayEquals(expectedText, dec);
    }

    @RepeatedTest(20)
    public void testSignWithGeneratedPAndQ() {
        val text = RandomStringUtils.randomAscii(1, 1_000_000).getBytes();
        val rsa = new RSA();
        val openPair = rsa.generatePublicKey();
        val privatePair = rsa.generatePrivateKey();

        val signedData = Signature.sign(text, openPair);

        Assertions.assertTrue(Signature.verify(text, signedData, privatePair));
    }

    @RepeatedTest(20)
    public void test() throws IOException {
        var input = Files.readAllBytes(Paths.get("C:\\Users\\niktv\\Downloads\\text.txt"));

        val rsa = new RSA();

        val openPair = rsa.generatePublicKey();
        val privatePair = rsa.generatePrivateKey();

        Signature.useStandardHashCode = false;

        val data = Signature.sign(input, openPair);

        Assertions.assertTrue(Signature.verify(input, data, privatePair));
    }
}
