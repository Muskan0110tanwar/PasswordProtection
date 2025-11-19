package com.security.checker;

import com.security.model.Password;
import com.security.exceptions.InvalidPasswordException;

public class StrengthChecker {
    public enum Classification { VERY_WEAK, WEAK, REASONABLE, STRONG, VERY_STRONG }

    public static Result evaluate(Password p) throws InvalidPasswordException {
        if (p == null) throw new InvalidPasswordException("Password object is null");
        String v = p.getValue();
        if (v == null || v.trim().isEmpty()) throw new InvalidPasswordException("Password is empty");
        int bits = p.calculateStrengthBits();
        int score = Math.min(100, bits * 2);
        Classification c;
        if (score < 20) c = Classification.VERY_WEAK;
        else if (score < 40) c = Classification.WEAK;
        else if (score < 60) c = Classification.REASONABLE;
        else if (score < 80) c = Classification.STRONG;
        else c = Classification.VERY_STRONG;
        return new Result(score, c, bits);
    }

    public static class Result {
        private final int score;
        private final Classification classification;
        private final int bits;
        public Result(int score, Classification classification, int bits) {
            this.score = score; this.classification = classification; this.bits = bits;
        }
        public int getScore(){ return score; }
        public Classification getClassification(){ return classification; }
        public int getBits(){ return bits; }
        @Override public String toString(){ return classification + " (" + score + ", " + bits + " bits)"; }
    }
}
