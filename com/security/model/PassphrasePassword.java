package com.security.model;

public class PassphrasePassword extends Password {
    public PassphrasePassword(long id, String value) {
        super(id, value);
    }

    @Override
    public int calculateStrengthBits() {
        String[] words = getValue().trim().split("\\s+");
        int bitsPerWord = 13; // approximate
        return words.length * bitsPerWord;
    }
}
