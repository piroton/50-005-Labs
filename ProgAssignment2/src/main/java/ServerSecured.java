import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * NOTE: This class uses the AESKeyHelper and RSAKeyHelper classes.
 * NOTE: You should work primarily on the TODO portions.
 *
 * The AESKeyHelper and RSAKeyHelper classes provide some useful means to decrypt and encrypt.
 * Otherwise, they're really just there to do key storage.
 */


public class ServerSecured {
    //    static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/";  // for junde
    static String serverPublicKeyFile = "example.org.public.der";
    static String serverPrivateKeyFile = "example.org.private.der";

    final static int CP_1_PACKET = 501;
    final static int CP_2_PACKET = 502;
    final static int FILE_HEADER_PACKET = 0;
    final static int FILE_DATA_PACKET = 1;
    final static int FILE_DIGEST_PACKET = 2;
    final static int PUB_KEY_PACKET = 101;
    final static int SEND_SESSION_KEY = 200;
    final static int SEND_TEST_MESSAGE = 201;
    final static int OK_PACKET = 80;

    // Note:
    // Mode = 1 is CP-1;
    // Mode = 2 is CP-2;
    private static int MODE;
    private static boolean modeHasBeenSet = false;
    private static PublicKey clientPublicKey;
    private static RSAKeyHelper serverKeys;
    static AESKeyHelper sessionKey;

    public static void main(String[] args) {
        System.out.println("Starting up Server...");
        System.out.print("Retrieving Keys...");
        try {
            serverKeys = new RSAKeyHelper(filedir + serverPublicKeyFile, filedir + serverPrivateKeyFile);
        } catch (Exception e) {
            System.out.println("Keys not found!");
//            e.printStackTrace();
        }
        System.out.println("done.");


        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            MessageDigest md = MessageDigest.getInstance("MD5");

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // TODO: PART 1


                // set MODE of cryptography for uploading; set helper mode.
                if (packetType == CP_1_PACKET && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    MODE = 1;
                }
                if (packetType == CP_2_PACKET && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    MODE = 2;
                    sessionKey = new AESKeyHelper();
                }

                // Inbound Public Key Packet
                if (packetType == PUB_KEY_PACKET) {

                    System.out.print("Receiving public key from client...");
                    byte[] clientPublicKeyBytes = new byte[128];
                    fromClient.readFully(clientPublicKeyBytes);

                    KeyFactory pubkf = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec clientKeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
                    clientPublicKey = pubkf.generatePublic(clientKeySpec);
                    System.out.println("Done.");
                }

                if (packetType == SEND_SESSION_KEY) {

                    int keyLen = fromClient.readInt();
                    System.out.print("Receiving session key from client...");
                    byte[] encodedKey = new byte[keyLen];
                    fromClient.read(encodedKey);
                    byte[] plainKeyBytes = serverKeys.decrypt(encodedKey, serverKeys.getPrivateKey());
                    SecretKey sentKey = new SecretKeySpec(plainKeyBytes, 0, plainKeyBytes.length, "AES");
                    sessionKey.setSharedKey(sentKey, keyLen);

                    int newPacket = fromClient.readInt();
                    if (newPacket == SEND_TEST_MESSAGE) {
                        byte[] replyMessage = sessionKey.encodeBytes(plainKeyBytes);
                        toClient.writeInt(replyMessage.length);
                        toClient.write(replyMessage);
                    }

                }

                // If the packet is for transferring the filename
                if (packetType == FILE_HEADER_PACKET) {


                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte[] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);

                    fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);


                } else if (packetType == FILE_DATA_PACKET) {
                    // If the packet is for transferring a chunk of the file

                    int numBytes = fromClient.readInt();
                    byte[] encodedBlock = new byte[numBytes];
                    fromClient.readFully(encodedBlock, 0, numBytes);
                    byte[] decryptedBlock = decryptChunk(encodedBlock);
                    numBytes = decryptedBlock.length;
                    md.update(decryptedBlock);


                    if (numBytes > 0)
                        bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);

                    if (numBytes < 117) {
                        // generate Digest, check against sent digest
                        byte[] digest = md.digest();
                        int digestLength = fromClient.readInt();
                        int digestPacket = fromClient.readInt();

                        if (digestPacket == FILE_DIGEST_PACKET) {
                            System.out.print("Verifying file...");
                            byte[] codedChecksum = new byte[digestLength];
                            fromClient.readFully(codedChecksum, 0, digestLength);
                            byte[] checksum = decryptChunk(codedChecksum);

                            if (checksum == digest) {
                                toClient.writeInt(OK_PACKET);
                            }
                            System.out.println("Done.");
                        }

                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                        modeHasBeenSet = false;
                    }
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    static byte[] decryptChunk(byte[] encrypted) throws Exception {
        /**
         * This function reads in the necessary packet-processing data from Client
         * Performs decryption on the data and returns the plain bytes according to the MODE
         * */
        // CP-1
        byte[] partiallyDecoded, plainBytes = null;
        if (MODE == 1) {
            partiallyDecoded = serverKeys.decrypt(encrypted, serverKeys.getPrivateKey());
            plainBytes = serverKeys.decrypt(partiallyDecoded, clientPublicKey);
        }
        // CP-2
        if (MODE == 2) {
            plainBytes = sessionKey.decodeBytes(encrypted);
        }
        return plainBytes;
    }

    static void theAuthentication() {
        /**
         This function will be called in tandem with the theAuthentication() function in client.
         Both enters function, do appropriate authentication procedures and exit their respective functions together.
         **/
    }
}
