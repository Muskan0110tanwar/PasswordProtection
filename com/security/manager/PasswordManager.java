package com.security.manager;

import com.security.model.Password;
import com.security.model.StrongPassword;
import com.security.model.PassphrasePassword;
import java.nio.file.*;
import java.util.*;
import java.io.*;
import java.security.SecureRandom;


public class PasswordManager {
    private final List<Password> list = new ArrayList<>();
    private long nextId = 1;
    private final Path historyFile;

    public PasswordManager(Path historyFile) {
        this.historyFile = historyFile;
        if (Files.exists(historyFile)) loadHistory();
    }

    public Password createStrong(int length, boolean upper, boolean lower, boolean digits, boolean special) {
        String pool = buildPool(upper, lower, digits, special);
        if (pool.isEmpty()) throw new IllegalArgumentException("Select at least one character class");
        Random rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i=0;i<length;i++) sb.append(pool.charAt(rnd.nextInt(pool.length())));
        StrongPassword p = new StrongPassword(nextId++, sb.toString());
        list.add(p);
        return p;
    }

    public Password createPassphrase(int words, List<String> wordlist) {
        if (wordlist == null || wordlist.isEmpty()) throw new IllegalArgumentException("Wordlist required");
        Random rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i=0;i<words;i++) {
            if (i>0) sb.append(' ');
            sb.append(wordlist.get(rnd.nextInt(wordlist.size())));
        }
        PassphrasePassword p = new PassphrasePassword(nextId++, sb.toString());
        list.add(p);
        return p;
    }

    private String buildPool(boolean upper, boolean lower, boolean digits, boolean special) {
        StringBuilder sb = new StringBuilder();
        if (upper) sb.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (lower) sb.append("abcdefghijklmnopqrstuvwxyz");
        if (digits) sb.append("0123456789");
        if (special) sb.append("!@#$%&*()-_=+[]{};:,.<>?");
        return sb.toString();
    }

    public List<Password> getSessionPasswords(){ return new ArrayList<>(list); }

    public void saveToHistory() throws IOException {
        Files.createDirectories(historyFile.getParent()==null?Paths.get("."):historyFile.getParent());
        try(BufferedWriter w = Files.newBufferedWriter(historyFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)){
            for (Password p: list) {
                w.write(p.getId()+"|"+p.getTimestamp()+"|"+p.getClass().getSimpleName()+"|"+escape(p.getValue()));
                w.newLine();
            }
        }
    }

    public void appendToHistory(Password p) throws IOException {
        Files.createDirectories(historyFile.getParent()==null?Paths.get("."):historyFile.getParent());
        try(BufferedWriter w = Files.newBufferedWriter(historyFile, StandardOpenOption.CREATE, StandardOpenOption.APPEND)){
            w.write(p.getId()+"|"+p.getTimestamp()+"|"+p.getClass().getSimpleName()+"|"+escape(p.getValue()));
            w.newLine();
        }
    }

    public void loadHistory(){
        if (!Files.exists(historyFile)) return;
        try(BufferedReader r = Files.newBufferedReader(historyFile)){
            String line; long maxId=0;
            while((line=r.readLine())!=null){
                String[] parts = line.split("\\|",4);
                if (parts.length<4) continue;
                long id = Long.parseLong(parts[0]);
                String type = parts[2];
                String value = unescape(parts[3]);
                if ("PassphrasePassword".equals(type)) list.add(new PassphrasePassword(id, value));
                else list.add(new StrongPassword(id, value));
                maxId = Math.max(maxId, id);
            }
            nextId = maxId+1;
        }catch(Exception e){ /* ignore malformed history */ }
    }

    private String escape(String v){ return v.replace("\\","\\\\").replace("|","\\|"); }
    private String unescape(String v){ return v.replace("\\|","|").replace("\\\\","\\"); }
}
