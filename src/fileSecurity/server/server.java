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
        public ConHandler(Socket socket)
        {
            this.socket = socket;

            try{
                in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                input = new Handlers.InReader(in);
                output = new Handlers.OutWriter(out);
                p("Streams are ready");
            }catch(Exception e){p("Error establishing streams");            }

            try{
                KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
                keyGen.init(256);
                sessionKey = keyGen.generateKey();
            }catch(Exception e){p("Problem generating Session Key");}
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
    }

    //Short print method
    static void p(String text)
    {
        System.out.println(text);
    }
}
