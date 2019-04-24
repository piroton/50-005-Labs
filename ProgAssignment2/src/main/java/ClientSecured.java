import javax.crypto.KeyGenerator;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.*;
import java.security.cert.*;

/**
 * NOTE: You should work primarily on the TODO portions.
 * <p>
 * The AESKeyHelper and RSAKeyHelper classes provide some useful means to decrypt and encrypt.
 * Otherwise, they're really just there to do key storage.
 */

public class ClientSecured {
    // static String filedir = "D:/github-repos/50-005-Labs/prog-assignment-2/";
    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/";  // for junde
    static String clientPublicKeyFile = "clientpublic.der";
    static String clientPrivateKeyFile = "clientkey.der";
    static String ca_public_key = "cacse.crt";
    static String filename = "sendomu.png";
    static String fullfilename = filedir + filename;
    static String serverAddress = "localhost";
//    static String serverAddress = "10.12.247.247";
    
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
    
    
    // PACKET SCHEMA:
    /*
    0: TRANSFER FILE NAME
    1: TRANSFER FILE CHUNK
    2: TRANSFER DIGEST
    102: TRANSFER PUBLIC KEY
    200: SEND SESSION KEY
    501: SET MODE TO CP-1
    502: SET MODE TO CP-2
    */
    
    
    // Mode = 1 is CP-1;
    // Mode = 2 is CP-2;
    /**
     * MODE: Set this to set the type of cryptography used by the file upload function.
     */
    private final static int MODE = 1;
    
    
    static RSAKeyHelper clientKeys;
    static PublicKey serverPublicKey;
    static KeyGenerator keyGen;
    static AESKeyHelper sessionKey;
    
    public static void main(String[] args) {
        
        if (args.length > 0) filename = args[0];
        if (args.length > 1) filename = args[1];
        
        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);
        
        int numBytes = 0;
        
        Socket clientSocket = null;
        
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
        
        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
        
        long timeStarted = System.nanoTime();
        
        try {
            
            System.out.println("Establishing connection to server...");
            
            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication START
            /**
             in order:
             1. Client sends nonce and message
             2. Server sends encrypted nonce (by server's private key) and certificate
             3. Client sends encrypted message (by server's public key)
             4. Server sends encrypted digest of message (by server's private key) and message
             **/
            final String encoding_type = "UTF-8";
            final String ok_message = "OK";
            byte[] nonce_message = new byte[200];
            byte[] received_message_byte = new byte[200];
            byte[] output_message_byte_encrypt;
            String received_message_string = null;
            int message_length;
            String message_length_string;
            
            
            // Step 0 - Constants
            System.out.println("Retrieving Client keys...");
            try {
                clientKeys = new RSAKeyHelper(filedir + clientPublicKeyFile, filedir + clientPrivateKeyFile);
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            
            // Step 1 - send message and nonce
            final String message = "HALLO THIS IS PATRICK";
            // final int nonce = 100;
            final int nonce = (int) (Math.random() * (900 - 100)) + 100;
            
            System.out.println("Client - Step 1");
            try {
                byte[] output_message_byte_decrypt = padAndSendBytes(Integer.toString(nonce) + message);
                toServer.write(output_message_byte_decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
            
            
            // Step 2 - Server sends encrypted nonce (length 256)
            byte[] encrypted_nonce = new byte[256];
            fromServer.readFully(encrypted_nonce);
            
            
            // Step 2 - Server sends certificate (length 1265)
            // receive certificate from server
            byte[] certificate = new byte[1265];
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // fromServer.readFully(certificate);
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fromServer);
            
            // retrieve CA public key
            File file = new File(filedir + ca_public_key);
            byte[] caPublicKeyArray = new byte[(int) file.length()];
            FileInputStream fis = new FileInputStream(file);
            X509Certificate CApublicKey = (X509Certificate) cf.generateCertificate(fis);
            try {
                CAcert.verify(CApublicKey.getPublicKey());  // if no exceptions are thrown, CAcert is verified. Negative example is w$
            } catch (Exception e) {
                e.printStackTrace();
            }
            serverPublicKey = CAcert.getPublicKey();
            // System.out.println(Arrays.toString(clientKeys.decrypt(encrypted_nonce, server_public_key)));  // verified server publi$
            
            
            // Step 3 - Client sends encrypted message (by server's public key)
            byte[] message_encrypted_server_public = clientKeys.encryptExternalRSA(padAndSendBytes(message), serverPublicKey);
            try {
                toServer.write(message_encrypted_server_public);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // System.out.println(Arrays.toString(message_encrypted_server_public));
            
            
            // Step 4 - server sends encrypted digest of message (by server's private key) (length of encrypted digest is 256)
            byte[] encrypted_message_digest = new byte[256];
            fromServer.readFully(encrypted_message_digest);
            byte[] decrypted_message_digest = clientKeys.decrypt(encrypted_message_digest, serverPublicKey);
            
            
            // Step 4 - server sends message
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] message_server = new byte[100];
            fromServer.readFully(message_server);
            byte[] new_message_digest = md.digest(message_server);
            boolean authenticated = Arrays.equals(new_message_digest, decrypted_message_digest);  // proves that the digest received i$

            // If not authenticated, stop connection
            if (!authenticated){
                return;
            }

            // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication END
            
            
            System.out.println("Initializing File Sending Process...");
            
            if (MODE == 1) {
                // MODE 1 describes CP-1 Style Cryptography: public-private double key signing
                System.out.println("CP-1 Mode Detected... Notifying server.");
                toServer.writeInt(CP_1_PACKET);
                
                System.out.print("Retrieving Client keys...");
                try {
                    clientKeys = new RSAKeyHelper(filedir + clientPublicKeyFile,
                            filedir + clientPrivateKeyFile);
                } catch (Exception e) {
                    // e.printStackTrace();
                    System.out.println("Key Files not found!");
                }
                System.out.println("done.");
                
                PublicKey pubKey = clientKeys.getPublicKey();
                
                System.out.println("Transmitting public key to Server...");
                toServer.writeInt(PUB_KEY_PACKET);
                byte[] bytePublicKey = pubKey.getEncoded();
                ByteArrayInputStream keyStream = new ByteArrayInputStream(bytePublicKey);
                sendChunksWithHeader(keyStream, 117, 128, SEND_SESSION_KEY, toServer);
                toServer.writeInt(STOP_PACKET);
            }
            
            if (MODE == 2) {
                /**
                 MODE 2 Describes Symmetric Key Cryptography: AES-128.
                 1. Notify Server that protocol is CP-2.
                 2. Generate Shared Key via AESKeyHelper class
                 3. Encode AES Key with Server Public Key
                 4. Send session key packet header.
                 5. Send session key.
                 6a. Receive encrypted bytes for verification. (encoded AES key)
                 6b. Verify that Server has the correct AES Key by decrypting bytes.
                 **/
                System.out.println("CP-2 Mode Detected... notifying server.");
                toServer.writeInt(CP_2_PACKET);
                
                System.out.print("Generating Shared Key...");
                sessionKey = new AESKeyHelper(128);
                System.out.println("done");
                
                System.out.print("Transmitting Session Key To Server...");
                toServer.writeInt(SEND_SESSION_KEY);
                byte[] plainKey = sessionKey.getSharedKey().getEncoded();
                
                toServer.writeInt(plainKey.length);
                byte[] encodedKey = clientKeys.encryptExternalRSA(plainKey, serverPublicKey);
                toServer.writeInt(encodedKey.length);
                toServer.write(encodedKey);
                
                System.out.print("Checking if Server has the correct key...");
                toServer.writeInt(SEND_TEST_MESSAGE);
                int replyLength = fromServer.readInt();
                byte[] encoded = new byte[replyLength];
                fromServer.read(encoded);
                byte[] replyMessage = sessionKey.decodeBytes(encoded);
                String reply = byteToStr(replyMessage);
                if (!reply.equals("F")) {
                    System.out.println("Server does not have key! Error!");
                }
            }
            
            
            System.out.print("Sending File now..");
            // Send the filename
            sendChunk(filename.getBytes(), toServer, FILE_HEADER_PACKET);
            //toServer.flush();
            
            // Open the file
            fileInputStream = new FileInputStream(fullfilename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);
            
            byte[] fromFileBuffer = new byte[117];
            // MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Send the file in chunks
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                md.update(fromFileBuffer);
                fileEnded = numBytes < 117;
                sendChunk(fromFileBuffer, toServer, FILE_DATA_PACKET);
                toServer.writeInt(numBytes);
                toServer.flush();
//                System.out.print(".");
            }
            System.out.println("done.");
            
            // Send Digest to Check
            System.out.print("Sending Digest to Verify.");
            byte[] digest = md.digest();
            System.out.print(".");
            sendChunk(digest, toServer, FILE_DIGEST_PACKET);
            System.out.print(".");
            
            int reply = fromServer.readInt();
            if (reply == OK_PACKET) {
                System.out.println("Success.");
            } else {
                System.out.println("Server reply timed out.");
            }
            System.out.println();
            
            System.out.println("Closing connection...");
            bufferedFileInputStream.close();
            fileInputStream.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
        
    }
    
    static void sendChunk(byte[] bytes, DataOutputStream toServer, int packetType) throws Exception {
        /**
         * sendChunk
         * byte[]           : bytes
         * DataOutputStream : toServer
         * int              : packetType
         *
         * Sends an integer represented by packetType (enumerated above) to "toServer".
         * Then, according to the MODE set in the class, encrypt bytes.
         * Then, send integer of length of encrypted byte array to "toServer'
         * And then the encrypted Bytes.
         * */
        
        toServer.writeInt(packetType);
//        System.out.println("DATA BLOCK SIZE:" + bytes.length);
        byte[] privateEncoded, bytesEncrypted;
        // CP-1
        if (MODE == 1) {
            bytesEncrypted= clientKeys.encryptExternalRSA(bytes, serverPublicKey);
//            System.out.println("DATA BLOCK SIZE:" + bytesEncrypted.length);
            
//            byte[] chunk1 = Arrays.copyOfRange(privateEncoded, 0, 127);
//            byte[] chunk2 = Arrays.copyOfRange(privateEncoded, 128, 255);
//            bytesEncrypted = clientKeys.encryptExternalRSA(chunk1, serverPublicKey);
//            byte[] bytesEncrypted2 = clientKeys.encryptExternalRSA(chunk2, serverPublicKey);
    
//            toServer.writeInt(bytesEncrypted.length);
//            toServer.write(bytesEncrypted);
//            toServer.writeInt(bytesEncrypted2.length);
//            toServer.write(bytesEncrypted2);
        }
        if (MODE == 2) {
            bytesEncrypted = sessionKey.encodeBytes(bytes);
        }
        toServer.writeInt(bytesEncrypted.length);
        toServer.write(bytesEncrypted);
        
    }
    
    static byte[] strToByte(String input) throws Exception {
        byte[] output = input.getBytes("UTF-8");
        return output;
    }
    
    static String byteToStr(byte[] input) {
        String output = new String(input);
        return output;
    }
    
    static void sendChunksWithHeader(ByteArrayInputStream rawdata, int chunkSize, int totalBytes,
                                     int dataPacketType, DataOutputStream outgoing) throws Exception {
        byte[] chunk = new byte[chunkSize];
        outgoing.writeInt(totalBytes);
        System.out.println(totalBytes+ "bytes");
        int bytesRead;
        for (boolean streamEnded = false; !streamEnded; ) {
            bytesRead = rawdata.read(chunk);
            byte[] encryptedChunk = clientKeys.encryptExternalRSA(chunk, serverPublicKey);
            streamEnded = bytesRead < chunkSize;
            outgoing.writeInt(dataPacketType);
            outgoing.writeInt(encryptedChunk.length);
            outgoing.write(encryptedChunk);
        }
        
        rawdata.close();
    }
    
    // @@ The Authentication START @@
    static final int byteArrayLength = 100;
    
    static byte[] padAndSendBytes(String input) {
        byte[] outputByteArray = null;
        int requiredStringLength = byteArrayLength;
        String paddedString;
        
        if (input.length() >= requiredStringLength) {
            System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ String is too long");
        }
        
        while (input.length() < requiredStringLength) {
            input = input + " ";
        }
        
        try {
            outputByteArray = input.getBytes("UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return outputByteArray;
    }
    
    static String stringConvertAndTrim(byte[] input) {
        String output = new String(input);
        int indexToSlice = output.length() - 1;
        
        while (output.charAt(indexToSlice) == ' ') {
            indexToSlice--;
        }
        
        output = output.substring(0, indexToSlice + 1);
        return output;
    }
    
    // @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ The Authentication END
}
