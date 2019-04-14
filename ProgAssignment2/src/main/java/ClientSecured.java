import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;

public class ClientSecured {
    
    public static void main(String[] args) {
        
        String filename = "rr.txt";
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
            
            System.out.println("Sending file...");
            
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
