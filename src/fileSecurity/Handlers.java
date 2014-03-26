package fileSecurity;

import java.io.BufferedReader;
import java.io.PrintWriter;

/**
 * Created by Daniel on 3/26/14.
 */
public class Handlers {

    public static class ResponseHandler
    {
        PrintWriter out;
        String responseString;

        public ResponseHandler(PrintWriter out)
        {
            this.out = out;
        }
    }

    public static class RequestHandler
    {
        BufferedReader in;
        String requestString;

        public RequestHandler(BufferedReader in)
        {
            this.in = in;
        }
    }

}
