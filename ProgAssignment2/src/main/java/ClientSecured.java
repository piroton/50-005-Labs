import javax.crypto.KeyGenerator;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * NOTE: You should work primarily on the TODO portions.
 *
 * The AESKeyHelper and RSAKeyHelper classes provide some useful means to decrypt and encrypt.
 * Otherwise, they're really just there to do key storage.
 * */

public class ClientSecured {
//    static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/";  // for junde
    static String clientPublicKeyFile = "clientpublic.der";
    static String clientPrivateKeyFile = "clientkey.der";
    
    final static int CP_1_PACKET = 501;
    final static int CP_2_PACKET = 502;
    final static int FILE_HEADER_PACKET = 0;
    final static int FILE_DATA_PACKET = 1;
    final static int FILE_DIGEST_PACKET = 2;
    final static int PUB_KEY_PACKET = 101;
    final static int SEND_SESSION_KEY = 200;
    final static int SEND_TEST_MESSAGE = 201;
    final static int OK_PACKET = 80;
    
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
     * */
    private final static int MODE = 1;
    
    
    static RSAKeyHelper clientKeys;
    static PublicKey serverPublicKey;
    static KeyGenerator keyGen;
    static AESKeyHelper sessionKey;
    
    public static void main(String[] args) {
        
        String filename = filedir + "rr.txt";
        if (args.length > 0) filename = args[0];
        
        String serverAddress = "localhost";
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
            
            // TODO: Request Encrypted Identity with Nonce
            // TODO: Store Reply Nonce
            // TODO: Store Identity
            // TODO: Request Signed Certificate with Encrypted Digest
            // TODO: Receive with Nonce, check Nonce against schema
            // TODO: Open certifying authority cert (cacse.crt) and decrypt with public key to verify
            // TODO: Open Signed Certificate and extract public key
            // TODO: Decrypt Message Digest and verify Message Digest
            // TODO: If all is well, continue; else, close socket
            
            
            System.out.print("Initializing File Sending Process...");
            
            if (MODE == 1) {
                /**
                 * MODE 1 describes CP-1 Style Cryptography: public-private double key signing
                 * Process:
                 * 1. Notify server that the protocol is CP-1.
                 * 2. Retrieve and set Client Keys.
                 * 3. Send the public key packet header.
                 * 4. Send the public key.
                 * */
                System.out.println("CP-1 Mode Detected... notifying server.");
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
                toServer.write(bytePublicKey);
            }
            
            if (MODE == 2) {
                /**
                 * MODE 2 Describes Symmetric Key Cryptography: AES-128.
                 * 1. Notify Server that protocol is CP-2.
                 * 2. Generate Shared Key via AESKeyHelper class
                 * 3. Encode AES Key with Server Public Key
                 * 4. Send session key packet header.
                 * 5. Send session key.
                 * 6a. Receive encrypted bytes for verification. (encoded AES key)
                 * 6b. Verify that Server has the correct AES Key by decrypting bytes.
                 * */
                System.out.println("CP-2 Mode Detected... notifying server.");
                toServer.writeInt(CP_2_PACKET);
                
                System.out.print("Generating Shared Key...");
                sessionKey = new AESKeyHelper(128);
                System.out.println("done");
                
                System.out.print("Transmitting Session Key To Server...");
                byte[] plainKey = sessionKey.getSharedKey().getEncoded();
                byte[] encodedKey = clientKeys.encryptExternalRSA(plainKey, serverPublicKey);
                toServer.writeInt(SEND_SESSION_KEY);
                toServer.writeInt(encodedKey.length);
                toServer.write(encodedKey);
                System.out.println("Done.");
                
                System.out.print("Checking if Server has the correct key...");
                toServer.writeInt(SEND_TEST_MESSAGE);
                int replyLength = fromServer.readInt();
                byte[] encoded = new byte[replyLength];
                fromServer.read(encoded);
                byte[] replyMessage = sessionKey.decodeBytes(encoded);
                if (replyMessage != plainKey) {
                    System.out.println("Server does not have key! Error!");
                }
            }
            
            System.out.print("Sending File now..");
            // Send the filename
            sendChunk(filename.getBytes(), toServer, FILE_HEADER_PACKET);
            //toServer.flush();
            
            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);
            
            byte[] fromFileBuffer = new byte[117];
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Send the file in chunks
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                md.update(fromFileBuffer);
                fileEnded = numBytes < 117;
                sendChunk(fromFileBuffer, toServer, FILE_DATA_PACKET);
                toServer.flush();
                System.out.print(".");
            }
            System.out.println("done.");
            
            // Send Digest to Check
            System.out.print("Sending Digest to Verify.");
            byte[] digest = md.digest();
            toServer.writeInt(digest.length);
            sendChunk(digest, toServer, FILE_DIGEST_PACKET);
            
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
        byte[] privateEncoded, bytesEncrypted;
        // CP-1
        if (MODE == 1) {
            privateEncoded = clientKeys.encryptPrivate(bytes);
            bytesEncrypted = clientKeys.encryptExternalRSA(privateEncoded, serverPublicKey);
        }
        if (MODE == 2) {
            bytesEncrypted = sessionKey.encodeBytes(bytes);
        }
        toServer.writeInt(bytesEncrypted.length);
        toServer.write(bytesEncrypted);
    }
    
    static void theAuthentication() {
        /**
         This function will be called in tandem with the theAuthentication() function in server.
         Both enters function, do appropriate authentication procedures and exit their respective functions together.
         
         1. Client says hello to server
         2.
         **/
    }
}
