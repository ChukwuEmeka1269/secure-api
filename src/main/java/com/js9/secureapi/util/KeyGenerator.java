package com.js9.secureapi.util;

import org.springframework.security.crypto.codec.Hex;

import java.security.SecureRandom;
import java.util.Arrays;

public class KeyGenerator {
    public static String generateHexKey(int keySizeInBytes) {
        // Generate random bytes
        byte[] keyBytes = new byte[keySizeInBytes];
        new SecureRandom().nextBytes(keyBytes);

        // Convert bytes to hexadecimal
        return Arrays.toString(Hex.encode(keyBytes));
    }

    public static void main(String[] args) {
        // Generate a 256-bit (32-byte) key in hexadecimal
        String hexKey = generateHexKey(32);
        System.out.println("Generated Key: " + hexKey);
    }
}
