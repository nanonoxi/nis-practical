package fileSecurity.server;
import fileSecurity.Cryptics;
import fileSecurity.Handlers;
import fileSecurity.keyGenerator.KeyGeneratorz;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.*;
import java.security.*;
import java.util.Random;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class Server {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }
    static ServerSocket socket;
    protected final static int port = 8087;

    private static PrivateKey serverPrivateKey;
    private static PublicKey clientPublicKey;
    private static Cryptics myCrypto;
    private static String dataFile = "serverdata.txt";
    private static ConHandler connection;
    private static boolean connected = false;

    public static void main(String args[])
    {
        try{
            clientPublicKey = (PublicKey)KeyGeneratorz.LoadKey("public","client");
            serverPrivateKey = (PrivateKey)KeyGeneratorz.LoadKey("private","server");
            p("Keys loaded!");
        }catch(Exception e)
        {
            p("Failed to load keys");
        }

        try{
            myCrypto = new Cryptics();
            //create a new socket connection
            socket = new ServerSocket(port);
            p("Socket waiting...");

            while(true)
            {
                if (socket.isClosed() || !connected)
                {
                    connection = new ConHandler(socket.accept());
                    p("Socket connected");
                    connection.engageHandshake();
                    connection.clientInterface();
                    connected = true;
                }else
                {
                    connection.clientInterface();
                }

            }
        }
        catch (IOException e){System.out.println("Error creating the socket on port:" + port);}
    }

    private static class ConHandler{
        private boolean authenticated = false;
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        private Handlers.OutWriter output;
        private Handlers.InReader input;
        private SecretKey sessionKey;
        private MessageDigest digest;

        public ConHandler(Socket socket)
        {
            this.socket = socket;

            try{
                in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                input = new Handlers.InReader(in);
                output = new Handlers.OutWriter(out);
                digest = MessageDigest.getInstance("SHA");
                p("Streams are ready");
            }catch(Exception e){p("Error establishing streams");            }

            try{
                KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
                keyGen.init(128);
                sessionKey = keyGen.generateKey();
            }catch(Exception e){p("Problem generating Session Key");}
        }

        public void clientInterface()
        {
            String choice = myCrypto.DecryptAES(input.readEncrypted(),sessionKey);
            output.sendEncrypted(myCrypto.EncryptAES("ack",sessionKey));
            int option = Integer.parseInt(choice);
            switch (option)
            {
                case 1://Upload a file
                {
                    fileDownloader(dataFile);
                    break;
                }

                case 2://Retrieve customer data
                {
                    //3. recieve ID
                    String id = (myCrypto.DecryptAES(input.readEncrypted(),sessionKey)).toUpperCase();
                    String record = retrieveLine(id);

                    //4. send File
                    output.sendEncrypted(myCrypto.EncryptAES(record,sessionKey));

                    //5. Recieve ack
                    System.out.println(myCrypto.DecryptAES(input.readEncrypted(),sessionKey));

                    break;
                }

                case 3://Verify Integrity of ServerSide data
                {
                    verifyIntegrity();
                    //4. the same?
                    output.sendEncrypted(myCrypto.EncryptAES(((verifyIntegrity())?"true":"false"),sessionKey));

                    break;
                }

            }
        }
        public void engageHandshake()
        {
            try
            {
                String message;
                String[] parts;

                //1.
                //Recieve Eus(ID,nonce)
                if ((message = myCrypto.DecryptRSAPrivate(input.readEncrypted(),serverPrivateKey))==null)
                {socket.close(); p("Key Mismatch");}
                parts = message.split(" ");

                //2.
                //Send Euc(nonce+1, Session key)
                int nonce = Integer.parseInt(parts[0])+1;
                String sKey = Base64.toBase64String(sessionKey.getEncoded());
                output.sendEncrypted(myCrypto.EncryptRSAPublic((nonce)+" "+sKey,clientPublicKey));

                //3.
                //Recieve Eus(Session key)
                message = myCrypto.DecryptRSAPrivate(input.readEncrypted(),serverPrivateKey);
                if (message.equals(sKey))
                    p("Handshaking Complete");

            }catch(Exception e)
            {
                p("Handsake failure");
            }
        }

        public void fileDownloader(String fileName)
        {
            try
            {
                //3. Download file from client
                String incomingFile= myCrypto.DecryptAES(input.readEncrypted(),sessionKey);

                String[] lines = incomingFile.split("\n");

                File file = new File(fileName);

                if (!file.exists())
                    file.createNewFile();

                FileWriter fw = new FileWriter(file);
                BufferedWriter bw = new BufferedWriter(fw);

                for ( int i=0; i < lines.length; i++)
                {
                    bw.write(lines[i]+"\n");
                }

                bw.close();

                p("Server data File Written");
                //4.
                output.sendEncrypted(myCrypto.EncryptAES("File Successfully uploaded to server",sessionKey));

            }catch (Exception e){p("stuff");}

        }

        public String retrieveLine(String ID)
        {
            String line=null;
            try{
            File file = new File(dataFile);
            BufferedReader br = new BufferedReader(new FileReader(file));
                while ((line=br.readLine())!=null)
                {
                    String id=line.split("\\|\\|")[0];
                    if (id.equals(ID))
                        return line;
                }
                p("ID: "+ID+ " Not found");
                return null;
            }catch(Exception e){ p("Failed to read server file"); return null;}
        }

        public boolean verifyIntegrity()
        {
            //3. Recieve ID and Hash
            String idandSignedHash = (myCrypto.DecryptAES(input.readEncrypted(),sessionKey));
            String parts[] = idandSignedHash.split("\\|\\|");

            String ID=parts[0];
            String clientSign = myCrypto.DecryptRSAPublic(Base64.decode(parts[1]),clientPublicKey);

            String[] localRecord = retrieveLine(ID).split("\\|\\|");

            if ( localRecord ==null)
            {
                System.out.println("Record Not on server");
                return false;
            }

            if (myCrypto.DecryptRSAPublic(Base64.decode(localRecord[2]),clientPublicKey).equals(clientSign))
                return true;

            return false;
        }
    }

    //Short print method
    static void p(String text)
    {
        System.out.println(text);
    }
}
