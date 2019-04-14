import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class ServerSecured {
    static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String serverPublicKeyFile = "example.org.public.der";
    static String serverPrivateKeyFile = "example.org.private.der";
    
    final static int cp1Packet = 501;
    final static int cp2Packet = 502;
    final static int pubKeyPacket = 102;
    final static int sendSessionKey = 200;
    final static int requestEndPleaseReply = 202;
    final static int fileHeaderPacket = 0;
    final static int fileDataPacket = 1;
    
    // Note:
    // Mode = 1 is CP-1;
    // Mode = 2 is CP-2;
    static int mode;
    static boolean modeHasBeenSet = false;
    static PublicKey clientKey;
    static RSAKeyPair serverKeys;
    
    public static void main(String[] args) {
        System.out.println("Starting up Server...");
        System.out.print("Retrieving Keys...");
        try {
            serverKeys = new RSAKeyPair(filedir+serverPublicKeyFile, filedir+serverPrivateKeyFile);
        } catch (Exception e){
            e.printStackTrace();
        }
        
        
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
            
            while (!connectionSocket.isClosed()) {
                
                int packetType = fromClient.readInt();
                
                // TODO: Read Request Packet from Client, use as Nonce
                // TODO: Reply with Nonce and Encrypted Identity
                // TODO: Read Request for Signed Certificate, Encrypt Digest of Cert
                
                // set mode of cryptography for uploading
                if (packetType == cp1Packet && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    mode = 1;
                }
                if (packetType == cp2Packet && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    mode = 2;
                }
                
                if (packetType == pubKeyPacket) {
                    System.out.print("Receiving public key from client...");
                    byte[] clientPublicKeyBytes = new byte[128];
                    fromClient.readFully(clientPublicKeyBytes);
                    
                    // reconstruct key from spec
                    KeyFactory pubkf = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec clientKeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
                    clientKey = pubkf.generatePublic(clientKeySpec);
                    
                    
                }
                
                // If the packet is for transferring the filename
                if (packetType == 0) {
                    
                    System.out.println("Receiving file...");
                    
                    int numBytes = fromClient.readInt();
                    byte[] filename = new byte[numBytes];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(filename, 0, numBytes);
                    
                    fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    
                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    
                    int numBytes = fromClient.readInt();
                    byte[] block = new byte[numBytes];
                    fromClient.readFully(block, 0, numBytes);
                    
                    if (numBytes > 0)
                        bufferedFileOutputStream.write(block, 0, numBytes);
                    
                    if (numBytes < 117) {
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
    
}
