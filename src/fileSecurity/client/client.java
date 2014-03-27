package fileSecurity.client;
import com.google.gson.GsonBuilder;
import fileSecurity.Cryptics;
import fileSecurity.Handlers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.*;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */


public class Client {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }



    //Socket to handle the connection to the server
    private static Socket clientSocket;

    private static BufferedReader in;
    private static PrintWriter out;
    private static Handlers.InReader input;
    private static Handlers.OutWriter output;
    private static Cryptics myCrypto;

    static String AESkey = "THIS is a KEY!";

    static String SERVER = "localhost";
    static final int PORT = 8087;


    public static void main(String args[])
    {
        myCrypto = new Cryptics(AESkey);
        connect();
    }

    static void connect ()
    {
        try
        {
            clientSocket = new Socket(InetAddress.getByName(SERVER),PORT);
            System.out.println("Connected to "+SERVER + "at port:" + PORT);

            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream());

            input = new Handlers.InReader(in);
            output = new Handlers.OutWriter(out);
            p("Streams ready");

            output.sendEncrypted(myCrypto.EncryptAES("YOU ARE A PIECAKE!"));


        }catch (IOException e){p("Error connecting with the server");
        }catch (Exception e){p("Something else went wrong 1."); e.printStackTrace();}

    }



    static void p(String text)
    {
        System.out.println(text);
    }

}