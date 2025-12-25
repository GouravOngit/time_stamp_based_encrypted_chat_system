import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * TickForge - A simple two-side chat simulator demonstrating a "timestamp-based" ephemeral-key
 * encryption mechanism. The timestamp is kept private (it is encrypted with the shared master secret)
 * and used to derive a per-message ephemeral key that encrypts the message. The receiver decrypts the
 * timestamp using the master key, derives the ephemeral key, verifies HMAC, then decrypts the message.
 *
 * Single-file Java program using Swing for GUI. This is educational code — NOT production-grade.
 */
public class tickforge {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new TickForgeFrame().setVisible(true));
    }
}

class TickForgeFrame extends JFrame {
    private final ChatPanel panelA;
    private final ChatPanel panelB;

    public TickForgeFrame() {
        setTitle("TickForge - Timestamp-based Encrypted Chat (Simulator)");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 600);
        setLayout(new BorderLayout());

        panelA = new ChatPanel("User A");
        panelB = new ChatPanel("User B");

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panelA, panelB);
        split.setResizeWeight(0.5);
        add(split, BorderLayout.CENTER);

        // Wire send actions to simulate message transfer: when A sends -> B receives, and vice versa
        panelA.setSendHandler((pkg) -> {
            panelA.appendLog("[SENT PACKAGE to User B]\n" + pkg);
            // Simulate network transfer: B attempts to receive
            String result = CryptoEngine.receivePackage(pkg, panelB.getMasterKey());
            panelB.appendLog("[RECEIVED PACKAGE]\nEncrypted package:\n" + pkg + "\n\nDecryption result:\n" + result);
        });

        panelB.setSendHandler((pkg) -> {
            panelB.appendLog("[SENT PACKAGE to User A]\n" + pkg);
            String result = CryptoEngine.receivePackage(pkg, panelA.getMasterKey());
            panelA.appendLog("[RECEIVED PACKAGE]\nEncrypted package:\n" + pkg + "\n\nDecryption result:\n" + result);
        });

        setLocationRelativeTo(null);
    }
}

class ChatPanel extends JPanel {
    private final JTextArea logArea = new JTextArea();
    private final JTextField inputField = new JTextField();
    private final JPasswordField masterKeyField = new JPasswordField();
    private SendHandler handler;

    public ChatPanel(String title) {
        setLayout(new BorderLayout());
        setBorder(new TitledBorder(title));

        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel("Master Key (shared): "), BorderLayout.WEST);
        masterKeyField.setEchoChar('*');
        masterKeyField.setText("shared-secret");
        top.add(masterKeyField, BorderLayout.CENTER);

        add(top, BorderLayout.NORTH);

        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);
        add(scroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(inputField, BorderLayout.CENTER);
        JButton sendBtn = new JButton("Send");
        bottom.add(sendBtn, BorderLayout.EAST);
        add(bottom, BorderLayout.SOUTH);

        sendBtn.addActionListener((ActionEvent e) -> send());
        inputField.addActionListener((ActionEvent e) -> send());
    }

    private void send() {
        String message = inputField.getText();
        if (message == null || message.isEmpty()) return;
        String master = getMasterKey();
        if (master == null || master.isEmpty()) {
            appendLog("Set a non-empty master key before sending.");
            return;
        }
        // Create package using CryptoEngine
        String pkg = CryptoEngine.createPackage(message, master);
        if (handler != null) handler.onSend(pkg);
        inputField.setText("");
    }

    public void appendLog(String text) {
        logArea.append(text + "\n\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    public void setSendHandler(SendHandler h) { this.handler = h; }

    public String getMasterKey() { return new String(masterKeyField.getPassword()); }

    interface SendHandler { void onSend(String pkg); }
}

class CryptoEngine {
    private static final SecureRandom rnd = new SecureRandom();
    private static final DateTimeFormatter fmt = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS");

    // Create a package string (Base64 components separated) that contains:
    // encTimestamp (AES-GCM with masterKey), tsIV, msgIV, ciphertext, hmac
    public static String createPackage(String message, String masterKey) {
        try {
            // 1) Create timestamp (private)
            String timestamp = LocalDateTime.now().format(fmt);

            // 2) Derive ephemeral key from masterKey and timestamp using HMAC-SHA256
            byte[] ephemeral = hmacSha256(masterKey.getBytes(StandardCharsets.UTF_8), timestamp.getBytes(StandardCharsets.UTF_8));
            // Truncate to 16 bytes for AES-128 key
            byte[] ephemeralKey = new byte[16];
            System.arraycopy(ephemeral, 0, ephemeralKey, 0, 16);

            // 3) Encrypt message with ephemeralKey using AES-GCM
            byte[] msgIV = new byte[12]; rnd.nextBytes(msgIV);
            byte[] ciphertext = aesGcmEncrypt(ephemeralKey, msgIV, message.getBytes(StandardCharsets.UTF_8), null);

            // 4) Encrypt timestamp with masterKey (so timestamp remains private during transit)
            byte[] masterKeyBytes = deriveKeyFromPassword(masterKey);
            byte[] tsIV = new byte[12]; rnd.nextBytes(tsIV);
            byte[] encTimestamp = aesGcmEncrypt(masterKeyBytes, tsIV, timestamp.getBytes(StandardCharsets.UTF_8), null);

            // 5) Compute HMAC of ciphertext using ephemeral key (message integrity/auth)
            byte[] hmac = hmacSha256(ephemeralKey, ciphertext);

            // 6) Package components into a single Base64 string (JSON would be nicer, but we keep it simple)
            String pkg = "encTs:" + b64(encTimestamp) + "|tsIV:" + b64(tsIV)
                    + "|msgIV:" + b64(msgIV) + "|ct:" + b64(ciphertext) + "|hmac:" + b64(hmac);
            return pkg;
        } catch (Exception e) {
            return "ERROR creating package: " + e.getMessage();
        }
    }

    // Receive package: decrypt timestamp with masterKey, derive ephemeral key, verify hmac, decrypt message
    public static String receivePackage(String packageString, String masterKey) {
        try {
            String[] parts = packageString.split("\\|");
            if (parts.length < 5) return "INVALID PACKAGE FORMAT";
            byte[] encTs = fromB64(parts[0].split(":",2)[1]);
            byte[] tsIV = fromB64(parts[1].split(":",2)[1]);
            byte[] msgIV = fromB64(parts[2].split(":",2)[1]);
            byte[] ct = fromB64(parts[3].split(":",2)[1]);
            byte[] hmac = fromB64(parts[4].split(":",2)[1]);

            // Decrypt timestamp with master key
            byte[] masterKeyBytes = deriveKeyFromPassword(masterKey);
            byte[] timestampBytes = aesGcmDecrypt(masterKeyBytes, tsIV, encTs, null);
            if (timestampBytes == null) return "FAILED: Cannot decrypt timestamp (wrong master key?)";
            String timestamp = new String(timestampBytes, StandardCharsets.UTF_8);

            // Derive ephemeral key from masterKey and timestamp
            byte[] ephemeral = hmacSha256(masterKey.getBytes(StandardCharsets.UTF_8), timestamp.getBytes(StandardCharsets.UTF_8));
            byte[] ephemeralKey = new byte[16]; System.arraycopy(ephemeral,0,ephemeralKey,0,16);

            // Verify HMAC
            byte[] expectedHmac = hmacSha256(ephemeralKey, ct);
            if (!MessageUtils.constTimeEquals(expectedHmac, hmac)) {
                return "FAILED: HMAC verification failed (message tampered or wrong master key/timestamp)";
            }

            // Decrypt ciphertext
            byte[] plain = aesGcmDecrypt(ephemeralKey, msgIV, ct, null);
            if (plain == null) return "FAILED: Cannot decrypt message";
            String message = new String(plain, StandardCharsets.UTF_8);

            return "OK\nTimestamp (private, recovered): " + timestamp + "\nMessage: " + message;
        } catch (Exception e) {
            return "ERROR receiving package: " + e.getMessage();
        }
    }

    // Utility: derive a stable 16/32 byte key from password (masterKey) using HMAC-SHA256 (simple KDF)
    private static byte[] deriveKeyFromPassword(String password) throws Exception {
        byte[] k = hmacSha256("TickForgeKDF".getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[16]; System.arraycopy(k,0,out,0,16); // AES-128
        return out;
    }

    private static byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plain, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec ks = new SecretKeySpec(key, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, ks, spec);
        if (aad != null) cipher.updateAAD(aad);
        return cipher.doFinal(plain);
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] cipherText, byte[] aad) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, ks, spec);
            if (aad != null) cipher.updateAAD(aad);
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            return null; // treat as decryption failure
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec ks = new SecretKeySpec(key, "HmacSHA256");
        mac.init(ks);
        return mac.doFinal(data);
    }

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] fromB64(String s) { return Base64.getDecoder().decode(s); }
}

class MessageUtils {
    // Constant-time equals to avoid timing attacks (small utility)
    public static boolean constTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) result |= a[i] ^ b[i];
        return result == 0;
    }
}
