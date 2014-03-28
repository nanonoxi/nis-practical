package fileSecurity;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.nio.CharBuffer;

/**
 * Created by Daniel on 3/26/14.
 */
public class Handlers {

    public static class OutWriter
    {
        PrintWriter output;
        String responseString;

        public OutWriter(PrintWriter out)
        {
            this.output = out;
        }

        public void send(String text)
        {
            output.write(text + "\n");
            output.flush();
        }

        //Send encrypted text
        public void send(byte[] cipherText)
        {
            for ( int i =0; i< cipherText.length; i++)
            {
                output.write(cipherText[i]);
            }
            output.write("\n");
            output.flush();
        }

        public void sendEncrypted(byte[] cipherText)
        {
            output.write(cipherText.length+" \n");
            for ( int i =0; i< cipherText.length; i++)
            {
                output.write(cipherText[i]);
            }
            output.flush();
        }

    }

    public static class InReader
    {
        BufferedReader input;
        String requestString;

        public InReader(BufferedReader in)
        {

            this.input = in;
        }

        public String read()
        {
            String result = "EISH!";

            try
            {while (!input.ready())
                {Thread.sleep(100);/*Wait for input! (Hopefully won't break anything!*/}
                result = input.readLine();
            }catch (Exception e){p("Not patient enough for input!"); e.printStackTrace();}

            return result;
        }

        public byte[] readEncrypted()
        {
            int length=0;
            try
            {
//                while (!input.ready())
//                {Thread.sleep(100);/*Wait for input! (Hopefully won't break anything!*/}
                 length = Integer.parseInt(input.readLine().trim());

            } catch(Exception e){p("Error reading size"); e.printStackTrace();}

            byte[] result = new byte[length];

            try
            {
            for (int i=0; i<length && input.ready(); i++)
            {
                result[i] = (byte)input.read();
            }
            }catch (Exception e){p("Not patient enough for input!"); e.printStackTrace();}

            return result;
        }
    }



    static void p(String printme)
    {System.out.println(printme);}

}
