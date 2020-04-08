package ru.hw.signature;

public class Utils {
    public static long unsignedInt(long number) {
        return number & 0xffffffffL;
    }
}
