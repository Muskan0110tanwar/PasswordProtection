package com.security.model;

public class StrongPassword extends Password {
    public StrongPassword(long id, String value) {
        super(id, value);
    }

    @Override
    public int calculateStrengthBits() {
        String v = getValue();
        boolean hasUpper = v.matches(".*[A-Z].*");
        boolean hasLower = v.matches(".*[a-z].*");
        boolean hasDigit = v.matches(".*\\d.*");
        boolean hasSpecial = v.matches(".*[^a-zA-Z0-9].*");
        int pool = 0;
        if (hasUpper) pool += 26;
        if (hasLower) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSpecial) pool += 32;
        if (pool == 0) return 0;
        double bits = v.length() * (Math.log(pool) / Math.log(2));
        return (int)Math.round(bits);
    }
}
