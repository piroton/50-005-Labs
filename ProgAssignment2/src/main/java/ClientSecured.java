import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientSecured {
    // static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/"  // for junde
    static String clientPublicKeyFile = "clientpublic.der";
    static String clientPrivateKeyFile = "clientkey.der";

    final static int CP_1_PACKET = 501;
    final static int CP_2_PACKET = 502;
    final static int FILE_HEADER_PACKET = 0;
    final static int FILE_DATA_PACKET = 1;
    final static int FILE_DIGEST_PACKET = 2;
    final static int PUB_KEY_PACKET = 102;
    final static int SEND_SESSION_KEY = 200;
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

    private final static int MODE = 1;
    static RSAKeyPair clientKeys;
    static PublicKey serverKey;
    static Key sessionKey;
    static byte[] filebytes;

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
                // DONE: CP-1 Style of Cryptography
                // DONE: Reply with public key
                // TODO: Encrypt file bytes with public key and then private key
                // TODO: Send Encrypted bytes

                System.out.println("CP-1 Mode Detected... notifying server.");
                toServer.writeInt(CP_1_PACKET);

                System.out.print("Retrieving Client keys...");
                try {
                    clientKeys = new RSAKeyPair(filedir + clientPublicKeyFile,
                            filedir + clientPrivateKeyFile);
                } catch (Exception e) {
                    // e.printStackTrace();
                    System.out.println("Key Files not found!");
                }
                System.out.println("done.");

                PrivateKey privKey = clientKeys.getPrivateKey();
                PublicKey pubKey = clientKeys.getPublicKey();

                System.out.println("Transmitting public key to Server...");
                toServer.writeInt(PUB_KEY_PACKET);
                byte[] bytePublicKey = pubKey.getEncoded();
                toServer.write(bytePublicKey);
            }
            if (MODE == 2){
                System.out.println("CP-2 Mode Detected... notifying server.");
                toServer.writeInt(CP_2_PACKET);
            }

            // TODO: CP-2 Style of Cryptography
            // TODO: Generate Session Key
            // TODO: Encrypt Session Key w/ SERVER Public
            // TODO: Send Encrypted Session Key w/ confirmation message
            // TODO: Receive Encrypted Confirmation w/ reply message (encrypted with AES key)
            // TODO: Decrypt Confirmation with AES key, confirm message
            // TODO: Encrypt bytes with session key

            System.out.print("Sending File now..");
            // Send the filename
            sendChunk(filename.getBytes(), toServer, FILE_HEADER_PACKET);
            //toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte[] fromFileBuffer = new byte[117];
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            // Send the file
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                md.update(fromFileBuffer);
                fileEnded = numBytes < 117;
                sendChunk(fromFileBuffer, toServer, FILE_DATA_PACKET);
                toServer.flush();
                System.out.print(".");
            }

            System.out.println("done.");
            System.out.print("Sending Digest to Verify.");

            // Send Digest to Check
            byte[] digest = md.digest();
            sendChunk(digest, toServer, FILE_DIGEST_PACKET);

            int reply = fromServer.readInt();
            if (reply == OK_PACKET){
                System.out.println("Success.");
                bufferedFileInputStream.close();
                fileInputStream.close();
            }
            System.out.println();

            System.out.println("Closing connection...");

        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    }

    static void sendChunk(byte[] bytes, DataOutputStream toServer, int packet_type) throws Exception{
        toServer.writeInt(packet_type);
        byte[] privateEncoded, bytesEncrypted;
        // CP-1
        if (MODE == 1){
            privateEncoded = clientKeys.encryptPrivate(bytes);
            bytesEncrypted = clientKeys.encryptExternalRSA(privateEncoded, serverKey);
        }
        if (MODE == 2){
            // TODO

        }

        toServer.writeInt(bytesEncrypted.length);
        toServer.write(bytesEncrypted);
    }

    static void theAuthentication(){
        /**
        This function will be called in tandem with the theAuthentication() function in server.
        Both enters function, do appropriate authentication procedures and exit their respective functions together.

        1. Client says hello to server
        2. 

        **/
    }
}
