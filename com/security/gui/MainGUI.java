package com.security.gui;

import com.security.manager.PasswordManager;
import com.security.model.Password;
import com.security.checker.StrengthChecker;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.file.Paths;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.IOException;

public class MainGUI {
    private JFrame frame;
    private JTextField txtLength;
    private JCheckBox cbUpper, cbLower, cbDigits, cbSpecial;
    private JTextArea outputArea;
    private PasswordManager manager;
    private List<String> wordlist;

    public MainGUI() {
        manager = new PasswordManager(Paths.get(System.getProperty("user.dir"), "history_gui.txt"));

        // Properly initialize wordlist as ArrayList
        wordlist = new ArrayList<>(Arrays.asList(
                "apple","banana","cherry","delta","echo","foxtrot","golf",
                "hotel","india","juliet","kilo","lima","mango","nectar","orange"
        ));

        buildUI();
    }

    private void buildUI() {
        frame = new JFrame("Password Generator - GUI");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(700, 450);
        frame.setLayout(new BorderLayout());

        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);

        c.gridx = 0; c.gridy = 0; top.add(new JLabel("Length:"), c);
        txtLength = new JTextField("12", 6); c.gridx = 1; top.add(txtLength, c);

        cbUpper = new JCheckBox("Upper", true); c.gridx = 2; top.add(cbUpper, c);
        cbLower = new JCheckBox("Lower", true); c.gridx = 3; top.add(cbLower, c);
        cbDigits = new JCheckBox("Digits", true); c.gridx = 4; top.add(cbDigits, c);
        cbSpecial = new JCheckBox("Special", false); c.gridx = 5; top.add(cbSpecial, c);

        JButton btnGen = new JButton("Generate Strong"); c.gridx = 6; top.add(btnGen, c);
        JButton btnPass = new JButton("Generate Passphrase"); c.gridx = 7; top.add(btnPass, c);

        frame.add(top, BorderLayout.NORTH);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        JScrollPane sp = new JScrollPane(outputArea);
        frame.add(sp, BorderLayout.CENTER);

        JPanel bottom = new JPanel();
        JButton btnCopy = new JButton("Copy Last");
        JButton btnSave = new JButton("Save History");
        JButton btnExit = new JButton("Exit");
        bottom.add(btnCopy); bottom.add(btnSave); bottom.add(btnExit);
        frame.add(bottom, BorderLayout.SOUTH);

        btnGen.addActionListener(e -> onGenerate());
        btnPass.addActionListener(e -> onPassphrase());
        btnCopy.addActionListener(e -> onCopy());
        btnSave.addActionListener(e -> onSave());
        btnExit.addActionListener(e -> System.exit(0));

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void onGenerate() {
        int len = 12;
        try { len = Integer.parseInt(txtLength.getText().trim()); } catch (Exception ex) { len = 12; }

        try {
            Password p = manager.createStrong(len, cbUpper.isSelected(), cbLower.isSelected(), cbDigits.isSelected(), cbSpecial.isSelected());
            manager.appendToHistory(p);
            displayPassword(p);
            int bits = p.calculateStrengthBits();
            StrengthChecker.Result r = StrengthChecker.evaluate(p);
            outputArea.append("\nEntropy bits: " + bits + " | " + r.toString() + "\n");

            int res = JOptionPane.showConfirmDialog(frame, "Save this password to history file?", "Save?", JOptionPane.YES_NO_OPTION);
            if (res == JOptionPane.YES_OPTION) {
                try {
                    manager.saveToHistory();
                    JOptionPane.showMessageDialog(frame, "Saved history.");
                } catch(IOException ioe) {
                    JOptionPane.showMessageDialog(frame, "Error saving: " + ioe.getMessage());
                }
            }
        } catch(Exception ex) {
            JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage());
        }
    }

    private void onPassphrase() {
        String words = JOptionPane.showInputDialog(frame, "How many words?", "4");
        int wc = 4;
        try { wc = Integer.parseInt(words); } catch(Exception ex) { wc = 4; }

        Password p = manager.createPassphrase(wc, wordlist);
        try { manager.appendToHistory(p); } catch(IOException e) {}
        displayPassword(p);

        try {
            StrengthChecker.Result r = StrengthChecker.evaluate(p);
            outputArea.append("\n" + r.toString() + "\n");
        } catch(Exception ex) {}

        int res = JOptionPane.showConfirmDialog(frame, "Save this passphrase to history file?", "Save?", JOptionPane.YES_NO_OPTION);
        if (res == JOptionPane.YES_OPTION) {
            try {
                manager.saveToHistory();
                JOptionPane.showMessageDialog(frame, "Saved history.");
            } catch(IOException ioe) {
                JOptionPane.showMessageDialog(frame, "Error saving: " + ioe.getMessage());
            }
        }
    }

    private void displayPassword(Password p) {
        outputArea.append("\nGenerated (id=" + p.getId() + "):\n" + p.getValue() + "\n");
    }

    private void onCopy() {
        String content = outputArea.getText().trim();
        if (content.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Nothing to copy");
            return;
        }
        String[] lines = content.split("\\n");
        String text = lines[lines.length - 1];
        StringSelection sel = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        JOptionPane.showMessageDialog(frame, "Last line copied to clipboard");
    }

    private void onSave() {
        try {
            manager.saveToHistory();
            JOptionPane.showMessageDialog(frame, "Saved history to file.");
        } catch(IOException e) {
            JOptionPane.showMessageDialog(frame, "Error saving: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(MainGUI::new);
    }
}
