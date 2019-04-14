import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ClientSecured {
    static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String clientPublicKeyFile = "clientpublic.der";
    static String clientPrivateKeyFile = "clientkey.der";
    static int pubKeyPacket = 102;
    static int sendSessionKey = 200;
    static int requestEndPleaseReply = 202;

    // PACKET SCHEMA:
    /*
    PACKET 0: TRANSFER FILE NAME
    PACKET 1: TRANSFER FILE CHUNK
    PACKET 102: TRANSFER PUBLIC KEY
    PACKET 200: SEND SESSION KEY
    PACKET 202: REQ OK RESPONSE
    * */



    // Note:
    // Mode = 1 is CP-1;
    // Mode = 2 is CP-2;
    final static int mode = 1;
    static RSAKeyPair clientKeys;
    static RSAKeyPair serverKeys;

    public static void main(String[] args) {
        
        String filename = filedir+"rr.txt";
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

            if (mode == 1){
                System.out.println("CP-1 Mode Detected.");
                try {
                    clientKeys = new RSAKeyPair(filedir + clientPublicKeyFile,
                            filedir+clientPrivateKeyFile);
                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("Key Files not found!");
                }

                PrivateKey privKey = clientKeys.getPrivateKey();
                PublicKey pubKey = clientKeys.getPublicKey();

                System.out.println("Transmitting public key to Server...");
                toServer.writeInt(pubKeyPacket);
                byte[] bytePublicKey = pubKey.getEncoded();
                toServer.write(bytePublicKey);


            }
            
            // TODO: CP-1 Style of Cryptography
            // TODO: Reply with public key
            // TODO: Encrypt file bytes with public key and then private key
            // TODO: Send Encrypted bytes
            
            // TODO: CP-2 Style of Cryptography
            // TODO: Generate Session Key
            // TODO: Encrypt Session Key w/ SERVER Public
            // TODO: Send Encrypted Session Key w/ confirmation message
            // TODO: Receive Encrypted Confirmation w/ reply message (encrypted with AES key)
            // TODO: Decrypt Confirmation with AES key, confirm message
            // TODO: Encrypt bytes with session key
            
            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());
            //toServer.flush();
            
            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);
            
            byte[] fromFileBuffer = new byte[117];
            
            // Send the file
            for (boolean fileEnded = false; !fileEnded; ) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;
                
                toServer.writeInt(1);
                toServer.writeInt(numBytes);
                toServer.write(fromFileBuffer);
                toServer.flush();
            }
            
            bufferedFileInputStream.close();
            fileInputStream.close();
            
            System.out.println("Closing connection...");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    }
}
