import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanismException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;

public class AESKeyHelper {
    private SecretKey sharedKey;
    private Cipher encoder;
    private int length;
    
    public AESKeyHelper(){
    }
    
    public AESKeyHelper(int length) {
        this.length = length;
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(length);
            sharedKey = generator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public SecretKey getSharedKey() {
        return sharedKey;
    }
    
    
    public void setSharedKey(SecretKey secret, int len){
        length = len;
        sharedKey = secret;
    }
    public int getLength(){ return length;}
    
    
    // Takes in plain byte[] and returns an AES-encrypted byte[] according to sharedKey
    public byte[] encodeBytes(byte[] plain){
        byte[] encrypted = null;
        try {
            encoder = Cipher.getInstance("AES");
            encoder.init(Cipher.ENCRYPT_MODE, sharedKey);
            encrypted = encoder.doFinal(plain);
        } catch (InvalidKeyException e) {
            System.out.println("ERROR: Invalid Key");
        } catch (Exception e){
            System.out.println("ERROR: Check block size.");
        } finally{
            return encrypted;
        }
    }
    
    
    // Decodes encrypted into plain via AES by sharedKey
    public byte[] decodeBytes(byte[] encrypted){
        byte[] plain = null;
        try {
            encoder = Cipher.getInstance("AES");
            encoder.init(Cipher.DECRYPT_MODE, sharedKey);
            plain = encoder.doFinal(encrypted);
        } catch (InvalidKeyException e) {
            System.out.println("ERROR: Invalid Key.");
        } catch (Exception e){
            System.out.println("ERROR: Check block size.");
        } finally{
            return plain;
        }
    }
}
