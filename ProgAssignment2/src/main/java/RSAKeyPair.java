import java.io.*;
import java.security.*;
import java.security.spec.*;


public class RSAKeyPair {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPair(String pubkey, String privkey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        File f = new File(privkey);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dataStream = new DataInputStream(fis);

        byte[] keyBytes = new byte[(int) f.length()];
        dataStream.readFully(keyBytes);
        dataStream.close();

        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(keyBytes);
        privateKey = keyFactory.generatePrivate(privateSpec);

        f = new File(pubkey);
        fis = new FileInputStream(f);
        dataStream = new DataInputStream(fis);

        byte[] pubKeyBytes = new byte[(int) f.length()];
        dataStream.readFully(pubKeyBytes);
        dataStream.close();

        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(pubKeyBytes);
        publicKey = keyFactory.generatePublic(publicSpec);
    }

    public RSAKeyPair(PublicKey pubKey, PrivateKey privKey){
        privateKey = privKey;
        publicKey = pubKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
