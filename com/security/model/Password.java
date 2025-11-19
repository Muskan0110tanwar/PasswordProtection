package com.security.model;

import java.time.Instant;

public abstract class Password {
    private final long id;
    private final String value;
    private final Instant timestamp;

    protected Password(long id, String value) {
        if (value == null) throw new IllegalArgumentException("Password cannot be null");
        this.id = id;
        this.value = value;
        this.timestamp = Instant.now();
    }

    public long getId() { return id; }
    public String getValue() { return value; }
    public Instant getTimestamp() { return timestamp; }

    public abstract int calculateStrengthBits();

    @Override
    public String toString() {
        return id + " | " + timestamp + " | " + mask(value);
    }

    private String mask(String v) {
        if (v.length() <= 4) return "****";
        return v.substring(0,2) + "..." + v.substring(v.length()-2);
    }
}
