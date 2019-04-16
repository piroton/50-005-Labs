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
    // static String filedir = "D:/Github/50-005-Labs/prog-assignment-2/";
    static String filedir = "/home/xubuntu/Desktop/50-005-Labs/prog-assignment-2/"  // for junde
    static String serverPublicKeyFile = "example.org.public.der";
    static String serverPrivateKeyFile = "example.org.private.der";

    final static int CP_1_PACKET = 501;
    final static int CP_2_PACKET = 502;
    final static int FILE_HEADER_PACKET = 0;
    final static int FILE_DATA_PACKET = 1;
    final static int FILE_DIGEST_PACKET = 2;
    final static int PUB_KEY_PACKET = 102;
    final static int SEND_SESSION_KEY = 200;

    // Note:
    // Mode = 1 is CP-1;
    // Mode = 2 is CP-2;
    private static int mode;
    private static boolean modeHasBeenSet = false;
    private static PublicKey clientKey;
    private static RSAKeyPair serverKeys;

    public static void main(String[] args) {
        System.out.println("Starting up Server...");
        System.out.print("Retrieving Keys...");
        try {
            serverKeys = new RSAKeyPair(filedir+serverPublicKeyFile, filedir+serverPrivateKeyFile);
        } catch (Exception e){
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

            while (!connectionSocket.isClosed()) {

                int packetType = fromClient.readInt();

                // TODO: Read Request Packet from Client, use as Nonce
                // TODO: Reply with Nonce and Encrypted Identity
                // TODO: Read Request for Signed Certificate, Encrypt Digest of Cert

                // set MODE of cryptography for uploading
                if (packetType == CP_1_PACKET && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    mode = 1;
                }
                if (packetType == CP_2_PACKET && !modeHasBeenSet) {
                    modeHasBeenSet = true;
                    mode = 2;
                }

                // Inbound Public Key Packet
                if (packetType == PUB_KEY_PACKET) {
                    System.out.print("Receiving public key from client...");
                    byte[] clientPublicKeyBytes = new byte[128];
                    fromClient.readFully(clientPublicKeyBytes);

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

    static byte[] decryptChunk(byte[] encrypted){
        //TODO
    }
    static void theAuthentication(){
        /**
        This function will be called in tandem with the theAuthentication() function in client.
        Both enters function, do appropriate authentication procedures and exit their respective functions together.
        **/
    }
}
