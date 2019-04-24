import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
    static String filedir = "D:/github-repos/50-005-Labs/prog-assignment-2/";
//    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/";  // for junde
    static String serverPublicKeyFile = "example.org.public.der";
    static String serverPrivateKeyFile = "example.org.private.der";
    static String caSignedFile = "example.org.crt";

    final static int CP_1_PACKET = 501;
    final static int CP_2_PACKET = 502;
    final static int FILE_HEADER_PACKET = 0;
    final static int FILE_DATA_PACKET = 1;
    final static int FILE_DIGEST_PACKET = 2;
    final static int PUB_KEY_PACKET = 101;
    final static int SEND_SESSION_KEY = 200;
    final static int SEND_TEST_MESSAGE = 201;
    final static int OK_PACKET = 80;
    final static int STOP_PACKET = 404;

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
        boolean authenticated = false;
        
        System.out.print("Listening for connection...");
        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            MessageDigest md = MessageDigest.getInstance("MD5");
            System.out.println("Connection found.");

            while (!connectionSocket.isClosed()) {

                if (!authenticated){
                    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication START
                    // Step 0
                    final String encoding_type = "UTF-8";
    
    
                    // Step 1 - Client sends nonce and message
                    System.out.println("Server - Step 1");
                    byte[] message_encrypt = new byte[100];
                    fromClient.readFully(message_encrypt);
                    String nonce_message = stringConvertAndTrim(message_encrypt);
                    String nonce = nonce_message.substring(0,3);
    
    
                    // Step 2 - Server sends encrypted nonce
                    byte[] nonce_bytes = padAndSendBytes(nonce);
                    byte[] encrypted_nonce_bytes = serverKeys.encryptPrivate(nonce_bytes);
                    try{
                        toClient.write(encrypted_nonce_bytes);
                    } catch (Exception e){
                        e.printStackTrace();
                    }
    
    
                    // Step 2 - Server sends certificate (signed cert is "example.org.crt", public key for cert is "cacse.crt")
                    File file = new File(filedir + caSignedFile);
                    byte[] bytesArray = new byte[(int) file.length()];  // length is 1265
                    FileInputStream fis = new FileInputStream(file);
                    fis.read(bytesArray);
                    fis.close();
                    toClient.write(bytesArray);
    
    
                    // Step 3 - Client sends encrypted message (by server's public key) (length of byte array is 256)
                    byte[] message_encrypted_server_public = new byte[256];
                    fromClient.readFully(message_encrypted_server_public);
                    String message_decrypted = stringConvertAndTrim(serverKeys.decrypt(message_encrypted_server_public, serverKeys.getPrivateKey()));
                    // System.out.println(nonce_message.substring(3).equals(message_decrypted));  // checking if decrypted message tallies fr$
    
    
                    // Step 4 - server sends encrypted digest of message (by server's private key)
                    // MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] message_digest = md.digest(padAndSendBytes(message_decrypted));
                    byte[] encrypted_message_digest = serverKeys.encryptPrivate(message_digest);
                    try{
                        toClient.write(encrypted_message_digest);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
    
    
                    // Step 4 - server sends message
                    try{
                        toClient.write(padAndSendBytes(message_decrypted));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    System.out.println("authentication done");
                    authenticated = true;
                }


                // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication END

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
                    int keyLen = fromClient.readInt();
                    byte[] clientPublicKeyBytes = receiveChunksMerge(128, STOP_PACKET, fromClient);
                    KeyFactory pubkf = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec clientKeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
                    clientPublicKey = pubkf.generatePublic(clientKeySpec);
                    System.out.println("Done.");
                }

                if (packetType == SEND_SESSION_KEY) {
                    System.out.print("Receiving session key from client...");
                    
                    int keyLen = fromClient.readInt();
                    System.out.println(keyLen);
                    int encodedKeyLen = fromClient.readInt();
                    byte[] encodedKey = new byte[encodedKeyLen];
                    fromClient.readFully(encodedKey);
                    
//                    System.out.println(len);
                    byte[] plainKeyBytes = serverKeys.decrypt(encodedKey, serverKeys.getPrivateKey());
//                    System.out.println(byteToStr(plainKeyBytes));
//                    System.arraycopy(keyp1, 0, plainKeyBytes, 0, 64);
//                    System.arraycopy(keyp2, 0, plainKeyBytes, 64, 64);
                    SecretKey sentKey = new SecretKeySpec(plainKeyBytes, 0, plainKeyBytes.length, "AES");
                    sessionKey.setSharedKey(sentKey, keyLen);
                    System.out.println("Done.");
                    
                    int callPacket = fromClient.readInt();
                    if (callPacket == SEND_TEST_MESSAGE){
                        byte[] testMessage = strToByte("F");
                        byte[] encodedTest = sessionKey.encodeBytes(testMessage);
                        toClient.writeInt(encodedTest.length);
                        toClient.write(encodedTest);
                    }
                    

                }

                // If the packet is for transferring the filename
                if (packetType == FILE_HEADER_PACKET) {


                    System.out.print("Receiving file header...");

                    int numBytes = fromClient.readInt();
                    byte[] encryptedFilename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(encryptedFilename, 0, numBytes);
                    byte[] filename = decryptChunk(encryptedFilename);
                    fileOutputStream = new FileOutputStream(filedir+"recv_" + new String(filename));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    
                    System.out.println("Done");


                } else if (packetType == FILE_DATA_PACKET) {
                    // If the packet is for transferring a chunk of the file
    
//                    System.out.println("Receiving file...");
                    int numBytes = fromClient.readInt();
                    byte[] encodedBlock = new byte[numBytes];
                    fromClient.readFully(encodedBlock);
                    int filebytes = fromClient.readInt();
                    byte[] decryptedBlock = decryptChunk(encodedBlock);
                    numBytes = decryptedBlock.length;
//                    System.out.print(numBytes);
                    md.update(decryptedBlock);


                    if (filebytes > 0)
                        bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);

                    if (filebytes < 117) {
                        System.out.println("File Ended, verifying now");
                        // generate Digest, check against sent digest
                        byte[] digest = md.digest();
                        String digested = Base64.getEncoder().encodeToString(digest);
                        int digestPacket = fromClient.readInt();
                        int digestLength = fromClient.readInt();

                        if (digestPacket == FILE_DIGEST_PACKET) {
                            System.out.print("Verifying file...");
                            byte[] codedChecksum = new byte[digestLength];
                            fromClient.readFully(codedChecksum, 0, digestLength);
                            byte[] checksum = decryptChunk(codedChecksum);
                            String compare = Base64.getEncoder().encodeToString(checksum);

                            if (compare.equals(digested)) {
                                toClient.writeInt(OK_PACKET);
                            } else {
                                toClient.writeInt(STOP_PACKET);
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
            plainBytes = serverKeys.decrypt(encrypted, serverKeys.getPrivateKey());
//            plainBytes = serverKeys.decrypt(partiallyDecoded, clientPublicKey);
//            System.out.println(new String(plainBytes));
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
    
    static byte[] receiveChunksMerge(int fullChunkSize, int stopPacket,
                                     DataInputStream incoming) throws Exception{
        ByteArrayOutputStream outputData = new ByteArrayOutputStream();
        while (incoming.readInt() != stopPacket){
            int datasize = incoming.readInt();
            byte[] data = new byte[datasize];
            incoming.readFully(data);
            byte[] output = new byte[fullChunkSize];
            output = serverKeys.decrypt(data, serverKeys.getPrivateKey());
            outputData.write(output);
        }
        byte[] allChunks = outputData.toByteArray();
        outputData.close();
        return allChunks;
    }

    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication START
    static final int byteArrayLength = 100;

    static byte[] padAndSendBytes(String input){
        byte[] outputByteArray = null;
        int requiredStringLength = byteArrayLength;
        String paddedString;

        if (input.length() >= requiredStringLength){
            System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ String is too long");
        }

        while (input.length() < requiredStringLength){
            input = input + " ";
        }

        try{
            outputByteArray = input.getBytes("UTF-8");
        }
        catch (Exception e){
            e.printStackTrace();
        }

        return outputByteArray;
    }

    static String stringConvertAndTrim(byte[] input){
        String output = new String(input);
        int indexToSlice = output.length()-1;

        while (output.charAt(indexToSlice) == ' '){
            indexToSlice --;
        }

        output = output.substring(0,indexToSlice+1);
        return output;
    }

    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication END



}
