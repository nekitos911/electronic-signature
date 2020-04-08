package ru.hw.signature;

public class Utils {
    public static long unsignedLong(long number) {
        return number & 0xffffffffL;
    }
}
