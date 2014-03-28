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
    private static String dataFile=null;

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


        while(true)
        {
            if (!connected)
            {
            connect();
            engageHandshake();
            }
            System.out.println("\nWelcome to our secure Client!\nInput your selection followed by Enter:");
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
            System.out.println("3. Remote record integrity check");
            System.out.println("4. Local record intergity check");
        }

        int in = Integer.parseInt(userInput.nextLine());

        switch (in)
        {
            case 1:
            {
                System.out.println("Please enter datafile name:");
                 String tex = userInput.nextLine();
                //1.
                 output.sendEncrypted(myCrypto.EncryptAES("1",sessionKey));
                //2.
                 if(myCrypto.DecryptAES(input.readEncrypted(),sessionKey).equals("ack"))
                    fileUploader(tex);
                 break;
            }
            case 2:
            {
                 System.out.println("Please enter ID:");
                 String id = userInput.nextLine().trim();
                 //1. init ID Retrieval
                 output.sendEncrypted(myCrypto.EncryptAES("2",sessionKey));

                //2. recieve ack
                if(myCrypto.DecryptAES(input.readEncrypted(),sessionKey).equals("ack"))
                {
                    System.out.println(id);
                    String serverRecord = remoteDataRetriever(id);
                    String decrypted = serverDataDecrypter(serverRecord);
                    p(decrypted);
                }
                 break;
            }
            case 3:
            {
                System.out.println("Verify Integrity of Remote data\n Please enter ID:");
                String id =userInput.nextLine().toUpperCase();
                //1.
                output.sendEncrypted(myCrypto.EncryptAES("3",sessionKey));
                //2.
                if(myCrypto.DecryptAES(input.readEncrypted(),sessionKey).equals("ack"))
                {
                    if(verifyRemoteRecord(id))
                        System.out.println("Remote record is intact");
                    else
                        System.out.println("IT'S A TRAP! -> Run for the hills!");
                }
            }
        }
    }

    //This calculates a Has of the record, sending it to the server - the serve will then compare these
    static boolean verifyRemoteRecord(String id)
    {

        String line = localDataRetriever(id);

        String[] parts = line.split("-");
        String details = parts[1];

        byte[] encDetail = myCrypto.EncryptAES(details);

        digest.reset();
        //HASH = Erc[HASH[ID||ENC[details]]]
        digest.update(parts[0].getBytes());
        digest.update(encDetail);
        String idandSignedHash = id+"||"+Base64.toBase64String(myCrypto.EncryptRSAPrivate(Base64.toBase64String(digest.digest()), clientPrivateKey));

        //3. Send Id and signed Hash
        output.sendEncrypted(myCrypto.EncryptAES(idandSignedHash,sessionKey));

        //4. Are they the same?

        return true;//(Boolean.parseBoolean(myCrypto.DecryptAES(input.readEncrypted(), sessionKey)));
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
            int nonce = rand.nextInt(9876);
            output.sendEncrypted(myCrypto.EncryptRSAPublic(""+nonce, serverPublicKey));

            //2.
            //Recieve Euc(Nonce+1, SessionKey)
            message = myCrypto.DecryptRSAPrivate(input.readEncrypted(),clientPrivateKey);
            parts = message.split(" ");
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

    static String localDataRetriever(String ID)
    {
        String line=null;
        try{
            if(dataFile==null)
            {
                System.out.println("Please enter dataFile name");
                dataFile = userInput.nextLine();
            }

            File file = new File(dataFile);
            BufferedReader br = new BufferedReader(new FileReader(file));
            while ((line=br.readLine())!=null)
            {
                String id=line.split("-")[0];
                if (id.equals(ID))
                    return line;
            }
            p("ID: "+ID+ " Not found");
            return null;
        }catch(Exception e){ p("Failed to read server file"); return null;}
    }

    static String remoteDataRetriever(String ID)
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