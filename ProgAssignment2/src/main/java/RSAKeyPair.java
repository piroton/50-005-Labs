import java.io.*;
import java.security.*;
import java.security.spec.*;


public class RSAKeyPair {
    public PrivateKey privateKey;
    public PublicKey publicKey;

    public RSAKeyPair(String keyfile) throws Exception {
        File f = new File(keyfile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dataStream = new DataInputStream(fis);

        byte[] keyBytes = new byte[(int) f.length()];
        dataStream.readFully(keyBytes);
        dataStream.close();

        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(keyBytes);
        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(privateSpec);
        publicKey = keyFactory.generatePublic(publicSpec);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
