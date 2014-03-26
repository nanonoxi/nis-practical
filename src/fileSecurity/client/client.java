package fileSecurity.client;
import com.google.gson.GsonBuilder;
import fileSecurity.Handlers;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.*;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class Client {
    //Socket to handle the connection to the server
    private Socket clientSocket;

    private InputStreamReader input;
    private OutputStreamWriter output;
    private static Handlers.ResponseHandler response;
    Handlers.RequestHandler request;

    String SERVER = "localhost";
    int PORT = 8087;


    public static void main(String args[])
    {
        //response = new Handlers.ResponseHandler();
    }

    void connect ()
    {

        try
        {
            clientSocket = new Socket(InetAddress.getByName(SERVER),PORT);
            System.out.println("Connected to "+SERVER + "at port:" + PORT);
        }catch (IOException e){p("Error connecting with the server");}

    }



    void p(String text)
    {
        System.out.println(text);
    }

}