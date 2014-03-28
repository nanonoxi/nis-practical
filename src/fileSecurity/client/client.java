package fileSecurity.client;
import com.google.gson.GsonBuilder;
import fileSecurity.Cryptics;
import fileSecurity.Handlers;
import fileSecurity.keyGenerator.KeyGeneratorz;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Random;
import java.util.Scanner;
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
    private static PrivateKey clientPrivateKey;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private static Scanner userInput;

    static String AESkey = "THIS is a KEY!";

    static String SERVER = "localhost";
    static final int PORT = 8087;


    public static void main(String args[])
    {
        try{
            clientPrivateKey = (PrivateKey)KeyGeneratorz.LoadKey("private","client");
            serverPublicKey = (PublicKey)KeyGeneratorz.LoadKey("public","server");
            p("Keys loaded!");
        }catch(Exception e)
        {
            p("Failed to load keys");
        }

        userInput = new Scanner(System.in);

        myCrypto = new Cryptics(AESkey);//Initialize Encryption Engine!
        connect();
        engageHandshake();

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
            //output.sendEncrypted(myCrypto.EncryptRSAPublic("YOU ARE A PIECAKE!",serverPublicKey));
        }catch (IOException e){p("Error connecting with the server");
        }catch (Exception e){p("Something else went wrong 1."); e.printStackTrace();}

    }

    static void engageHandshake()
    {
        try
        {
            String message;
            String[] parts;
            Random rand = new Random();

            //1.
            //Send Eus(ID, Nonce)
            System.out.println("Enter ID:");
            String id = userInput.nextLine();
            int nonce = rand.nextInt(9876);
            output.sendEncrypted(myCrypto.EncryptRSAPublic(id + " " + nonce, serverPublicKey));

            //2.
            //Recieve Euc(Nonce+1, SessionKey)
            message = myCrypto.DecryptRSAPrivate(input.readEncrypted(),clientPrivateKey);
            parts = message.split(" ");
            p(nonce + " " + parts[0]);
            byte[] encodedKey = Base64.decode(parts[1]);
            sessionKey = new SecretKeySpec(encodedKey,0,encodedKey.length,"AES");

            //Send Eus(Sessionkey)
            output.sendEncrypted(myCrypto.EncryptRSAPublic(parts[1],serverPublicKey));

            //Send encrypted file-> Esk(Id, encodedFile);







        }catch(Exception e)
        {
            p("Handshake Failure");
        }
    }



    static void p(String text)
    {
        System.out.println(text);
    }

}