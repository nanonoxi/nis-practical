package fileSecurity.server;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.*;
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

            while(true)
            {
                ConHandler connection = new ConHandler(socket.accept());
            }

        }
        catch (IOException e){System.out.println("Error creating the socket on port:" + port);}
    }

    private static class ConHandler{
        private boolean authenticated = false;
        private Socket socket;

        public ConHandler(Socket socket)
        {
            this.socket = socket;
        }

    }
    //printHelper
    static void p(String text)
    {
        System.out.println(text);
    }
}
