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
                ConHandler connection = new ConHandler(socket.accept());
                p("Socket connected");
                connection.engageHandshake();
                connection.clientInterface();
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
            char option = (char)choice.charAt(0);
            switch (option)
            {
                case 'u'://Upload a file
                    fileDownloader(dataFile);
                    break;
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
                int nonce = Integer.parseInt(parts[1])+1;
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
                    String id;

                    if ((id=(line.split("||"))[0]).equals(ID))
                        return line;
                }
                p("ID: "+ID+ " Not found");
                return null;
            }catch(Exception e){ p("Failed to read server file"); return null;}
        }

        public boolean verifyIntegrity(String ID)
        {
            String[] file = retrieveLine(ID).split("||");

            if ( file ==null)
            {
                System.out.println("ID Not found");
                return false;
            }

            digest.reset();
            digest.update(file[0].getBytes());
            digest.update(file[1].getBytes());

            String calcHash = Base64.toBase64String(digest.digest());
            if (calcHash.equals(file[2]))
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
