package ru.hw.signature.benchmark;

import lombok.SneakyThrows;
import lombok.val;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import ru.hw.signature.RSA;
import ru.hw.signature.Signature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Benchmark {
    private static int ITERATIONS = 10;
    private static int SIZE = 1_000_000;
    private static final String FOLDER = "benchmarks/";
    private static final String FILE = FOLDER + "benchmark.txt";

    public static void main(String[] args) throws IOException {
        val signWithDefault = benchmarkSignWithDefaultPAndQ();
        val signWithCustom = benchmarkSignWithCustomPAndQAndE();
        val verify = benchmarkVerify();

        if (!Files.exists(Paths.get(FOLDER))) {
            Files.createDirectory(Paths.get(FOLDER));
        }

        Files.write(Paths.get(FILE), ("=".repeat(50) + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), (LocalDateTime.now().toString() + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("iterations: " + ITERATIONS + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("data size: " + SIZE + " bytes" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("sign with auto generated p, q, e: " + signWithDefault + " ms" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("sign with custom p, q, e: " + signWithCustom + " ms" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("verify sign: " + verify + " ms" + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        Files.write(Paths.get(FILE), ("=".repeat(50) + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    @SneakyThrows
    private static long benchmarkSignWithDefaultPAndQ() {
        val data = RandomStringUtils.randomAscii(SIZE).getBytes();

        byte[] res = null;
        var begin = Instant.now();
        for (int i = 0; i < ITERATIONS; i++) {
            val rsa = new RSA().init();
            val signature = new Signature(rsa);
            val openKey = signature.generatePublicKey();
            res = Signature.sign(data, openKey);
        }
        val duration = Duration.between(begin, Instant.now()).abs().toMillis() / ITERATIONS;
        System.out.println(res);
        return duration;
    }

    @SneakyThrows
    private static long benchmarkSignWithCustomPAndQAndE() {
        val data = RandomStringUtils.randomAscii(SIZE).getBytes();

        byte[] res = null;
        var begin = Instant.now();
        for (int i = 0; i < ITERATIONS; i++) {
            val p = new BigInteger("5700734181645378434561188374130529072194886062117");
            val q = new BigInteger("35894562752016259689151502540913447503526083241413");
            val e = new BigInteger("33445843524692047286771520482406772494816708076993");
            val rsa = new RSA().init(p, q, e);
            val signature = new Signature(rsa);
            val openKey = signature.generatePublicKey();
            res = Signature.sign(data, openKey);
        }
        val duration = Duration.between(begin, Instant.now()).abs().toMillis() / ITERATIONS;
        System.out.println(res);
        return duration;
    }

    @SneakyThrows
    private static long benchmarkVerify() {
        val data = RandomStringUtils.randomAscii(SIZE).getBytes();

        boolean res = false;
        val signed = IntStream.range(0, ITERATIONS)
                .mapToObj(i -> new Signature(new RSA().init()))
                .map(sig -> new ImmutablePair<>(Signature.sign(data, sig.generatePublicKey()), sig.generatePrivateKey()))
                .collect(Collectors.toList());

        var begin = Instant.now();
        for (var pair : signed) {
            res = Signature.verify(data, pair.left, pair.right);
        }
        val duration = Duration.between(begin, Instant.now()).abs().toMillis() / ITERATIONS;
        System.out.println(res);
        return duration;
    }
}
