package fileSecurity.client;
import com.google.gson.GsonBuilder;
import fileSecurity.Cryptics;
import fileSecurity.Handlers;
import fileSecurity.keyGenerator.KeyGeneratorz;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import sun.print.resources.serviceui_es;

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
    private static SecretKey masterKey;
    private static Scanner userInput;
    private static MessageDigest digest;
    private static boolean connected = false;

    static String AESkey = "THIS is a KEY!";

    static String SERVER = "localhost";
    static final int PORT = 8087;


    public static void main(String args[])
    {
        try{
            KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
            keyGen.init(128);
            masterKey = keyGen.generateKey();
        }catch(Exception e){p("Problem generating Session Key");}

        try{
            clientPrivateKey = (PrivateKey)KeyGeneratorz.LoadKey("private","client");
            serverPublicKey = (PublicKey)KeyGeneratorz.LoadKey("public","server");
            digest = MessageDigest.getInstance("SHA");
            p("Keys loaded!");
        }catch(Exception e)
        {
            p("Failed to load keys");
        }

        userInput = new Scanner(System.in);

        myCrypto = new Cryptics(AESkey);//Initialize Encryption Engine!

        System.out.println("Welcome to our secure Client!\nInput your selection followed by Enter:\n");
        while(true)
        {
            if (!connected)
            {
            connect();
            engageHandshake();
            }
            menu();
        }
    }

    static void menu()
    {

        if(connected)
        {
            System.out.println("--Menu--");
            System.out.println("1. Upload data file ");
            System.out.println("2. Retrieve customer information" );
            System.out.println("3. Verify information");
        }

        int in = Integer.parseInt(userInput.nextLine());

        switch (in)
        {
            case 1:
            {
                System.out.println("Please enter datafile name:");
                 String tex = userInput.nextLine();
                //1.
                 output.sendEncrypted(myCrypto.EncryptAES("u",sessionKey));
                //2.
                 if(myCrypto.DecryptAES(input.readEncrypted(),sessionKey).equals("ack"))
                    fileUploader(tex);
                 break;
            }
            case 2:
                 System.out.println("Please enter ID:");
                 String id = userInput.nextLine().trim();
                 //1. init ID Retrieval
                 output.sendEncrypted(myCrypto.EncryptAES("r",sessionKey));

                //2. recieve ack
                if(myCrypto.DecryptAES(input.readEncrypted(),sessionKey).equals("ack"))
                {
                    System.out.println(id);
                    String serverRecord = dataRetriever(id);
                    String decrypted = serverDataDecrypter(serverRecord);
                    p(decrypted);
                }
                 break;

        }
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
            p(parts[1]);
            byte[] encodedKey = Base64.decode(parts[1]);
            sessionKey = new SecretKeySpec(encodedKey,0,encodedKey.length,"AES");

            //Send Eus(Sessionkey)
            output.sendEncrypted(myCrypto.EncryptRSAPublic(parts[1], serverPublicKey));

        }catch(Exception e)
        {
            p("Handshake Failure");
        }

        connected = true;
    }


    static String dataRetriever(String ID)
    {
        String record=null;
        try{
            //3. Send ID to server
            output.sendEncrypted(myCrypto.EncryptAES(ID,sessionKey));

            //4. recieve file
            record =myCrypto.DecryptAES(input.readEncrypted(),sessionKey);
            //System.out.println(record);

            //5. Send Ack
            output.sendEncrypted(myCrypto.EncryptAES("Client has recieved file",sessionKey));


        }catch(Exception e)
        {
            p("Failed to retrieve line");
        }

        return record;
    }

    static String serverDataDecrypter(String partial)
    {
        String[] parts = partial.split("\\|\\|");
        String details = myCrypto.DecryptAES(Base64.decode(parts[1]));

        String decrypted=parts[0]+"-"+details;
        return decrypted;
    }

    static void fileUploader(String fileName)
    {
        try
        {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuffer eBuilder = new StringBuffer();

            String unprocessedLine;

            while ((unprocessedLine = reader.readLine())!=null)
            {
                digest.reset();
                String[] prepped = unprocessedLine.split("-");
                String ID=prepped[0], details=prepped[1];

                //Emk[Details] - Emk encrypted with master key
                byte[] encDetail = myCrypto.EncryptAES(details);

                //HASH = Erc[HASH[ID||ENC[details]]]
                digest.update(ID.getBytes());
                digest.update(encDetail);
                String hash = Base64.toBase64String(myCrypto.EncryptRSAPrivate(Base64.toBase64String(digest.digest()), clientPrivateKey));

                //Append to a String representing the whole file
                eBuilder.append(ID + "||" + Base64.toBase64String(encDetail) + "||" + hash + "\n");
            }

            String preFile = eBuilder.toString();
            //3
            output.sendEncrypted(myCrypto.EncryptAES(preFile, sessionKey));

            //Print Server ack
            //4.
            System.out.println(myCrypto.DecryptAES(input.readEncrypted(),sessionKey));
        }catch (FileNotFoundException e){p("File not Found!");
        }catch (IOException e){p("Error reading file contents");
        }
    }

    static void p(String text)
    {
        System.out.println(text);
    }

}