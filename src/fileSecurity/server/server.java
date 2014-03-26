package fileSecurity.server;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.net.*;
/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class server {

    static ServerSocket socket;
    protected final static int port = 8081;

    public static void main(String args[])
    {
        try{
            //create a new socket connection
            socket = new ServerSocket(port);
            p("Socket has been Initialized");


        }
        catch (IOException e){System.out.println("Error creating the socket on port:" + port);}
    }

    private static class ConHandler extends Thread{
        private boolean authenticated = false;
    }
    //printHelper
    static void p(String text)
    {
        System.out.println(text);
    }
}
