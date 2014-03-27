package fileSecurity.server;
import fileSecurity.Cryptics;
import fileSecurity.Handlers;

import java.io.*;
import java.net.ServerSocket;
import java.net.*;
import java.security.*;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class Server {

    static ServerSocket socket;
    protected final static int port = 8087;

    public static void main(String args[])
    {
        try{
            //create a new socket connection
            socket = new ServerSocket(port);
            p("Socket has been Initialized");

            while(true)
            {
                ConHandler connection = new ConHandler(socket.accept());
                p("Socket connection attempt made");

                connection.printStuff();
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
        }

        public void printStuff()
        {
            //byte[] t = input.re();
            byte[] test =  input.readEncrypted();
            String AESkey = "THIS is a KEY!";
            Cryptics myCrypto = new Cryptics(AESkey);
            System.out.println(myCrypto.DecryptAES(test));
        }
    }

    //Short print method
    static void p(String text)
    {
        System.out.println(text);
    }
}
