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
import java.util.*;


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

            // The Authentication START
            int server_state = 1;
            String message = null;
            byte[] message_encrypt = new byte[200];

            // The Authentication END


            while (!connectionSocket.isClosed()) {

                // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication START
                // bug: printed string came out wrong. tried: converting received byte array to string using US_ASCII;

                final String encoding_type = "UTF-16";
                final String message1 = "HALLO POLLY WANTS A CRACKER";  // treat this as a standard message protocol
                final int nonce = 100;
                final String ok_message = "OK";
                final int message_length = 50;
                String output_message;
                byte[] output_message_byte_decrypt;
                byte[] output_message_byte_encrypt;
                String received_message_string = null;

/**
                if (server_state == 1){
                    // Step 1
                    System.out.println("Server - Step 1");
                    while (message == null){
                        message = fromClient.readUTF();
                    }
                    server_state = 2;
                }
                else if (server_state == 2) {
                    // Step 2
                    // sends OK
                    System.out.println("Server - Step 2");
                    try{
                        toClient.writeUTF(ok_message);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    server_state = 3;
                }
                else if (server_state == 3){
                    // Step 3
                    System.out.println("Server - Step 3");
                    while (received_message_string == null){
                        received_message_string = fromClient.readUTF();
                    }
                    if (received_message_string.equals(message1)){
                        System.out.println("message1 received by server");
                        server_state = 4;
                        received_message_string = null;
                    }
                }
                else if (server_state == 4){
                    // Step 4
                    System.out.println("Server - Step 4");
                    try{
                        output_message = Integer.toString(nonce) + message;
                        output_message_byte_decrypt = output_message.getBytes();
                        output_message_byte_encrypt = serverKeys.encryptPrivate(output_message_byte_decrypt);

                        toClient.write(output_message_byte_encrypt);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    server_state = 5;
                }
                else if (server_state == 5){
                    // Step 5
                    fromClient.readFully(message_encrypt);
                    System.out.println(Arrays.toString(message_encrypt));
                }
**/
                    // Step 1
                    System.out.println("Server - Step 1");
                    while (message == null){
                        message = fromClient.readUTF();
                    }
                    server_state = 2;

                    // Step 2
                    // sends OK
                    System.out.println("Server - Step 2");
                    try{
                        toClient.writeUTF(ok_message);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    server_state = 3;

                    // Step 3
                    System.out.println("Server - Step 3");
                    while (received_message_string == null){
                        received_message_string = fromClient.readUTF();
                    }
                    if (received_message_string.equals(message1)){
                        server_state = 4;
                        received_message_string = null;
                    }

                    // Step 4
                    System.out.println("Server - Step 4");
                    try{
                        output_message = Integer.toString(nonce) + message;
                        output_message_byte_decrypt = output_message.getBytes("UTF-16");
                        output_message_byte_encrypt = serverKeys.encryptPrivate(output_message_byte_decrypt);

                        toClient.write(output_message_byte_encrypt);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    server_state = 5;

                    // Step 5
                    System.out.println("Server - Step 5");
                    fromClient.readFully(message_encrypt);
                    System.out.println(Arrays.toString(message_encrypt));



                // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication END
                /**

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
                **/
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

    static byte[] strToByte(String input) throws Exception{
        byte[] output = input.getBytes("UTF-8");
        return output;
    }

    static String byteToStr(byte[] input){
        String output = new String(input);
        return output;
    }
}
