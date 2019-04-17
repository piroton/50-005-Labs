import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.*;


public class RSAKeyHelper {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher RSAcipher;
    
    byte[] getKeyBytes(String dir) throws Exception {
        File f = new File(dir);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dataStream = new DataInputStream(fis);
        
        byte[] keyBytes = new byte[(int) f.length()];
        dataStream.readFully(keyBytes);
        dataStream.close();
        return keyBytes;
    }
    
    public RSAKeyHelper(String pubkey_dir, String privkey_dir) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        byte[] privateKeyBytes = getKeyBytes(privkey_dir);
        byte[] pubKeyBytes = getKeyBytes(pubkey_dir);
        
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        privateKey = keyFactory.generatePrivate(privateSpec);
        
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(pubKeyBytes);
        publicKey = keyFactory.generatePublic(publicSpec);
    
        RSAcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }
    
    public RSAKeyHelper(PublicKey pubKey, PrivateKey privKey) {
        privateKey = privKey;
        publicKey = pubKey;
    }
    
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * inputs: byte[]: plaintext
     * outputs: byte[]: cipheredtext
     *
     * Processes plaintext by encrypting it with the PUBLIC key contained in this class.
     * */
    public byte[] encryptPublic(byte[] plaintext) throws Exception {
        RSAcipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipheredPublic = RSAcipher.doFinal(plaintext);
        return cipheredPublic;
    }
    
    /**
     * inputs: byte[]: plaintext
     * outputs: byte[]: cipheredtext
     *
     * Processes plaintext by encrypting it with the PRIVATE key contained in this class.
     * */
    public byte[] encryptPrivate(byte[] plaintext) throws Exception {
        RSAcipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipheredPrivate = RSAcipher.doFinal(plaintext);
        return cipheredPrivate;
    }
    
    
    /**
     * inputs:
     * byte[]   : encrypted
     * Key      : key
     * outputs: byte[]: cipheredtext
     *
     * decrypts ciphertext with the private/public Key passed in.
     * */
    public byte[] decrypt(byte[] encrypted, Key key) throws Exception{
        RSAcipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = RSAcipher.doFinal(encrypted);
        return decrypted;
    }
    
    /**
     * inputs:
     * byte[]   : plaintext
     * Key      : key
     * outputs: byte[]: cipheredtext
     *
     * encrypts plaintext with the private/public Key passed in.
     * */
    public byte[] encryptExternalRSA(byte[] plaintext, Key key) throws Exception{
        RSAcipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = RSAcipher.doFinal(plaintext);
        return encrypted;
    }
}
