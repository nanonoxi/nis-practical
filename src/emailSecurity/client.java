package emailSecurity;

import java.security.Security;
import java.util.logging.Logger;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 */
public class Client {

    private static final Logger LOGGER = Logger.getLogger(Client.class.getName());


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private void run() {
        System.out.println("Hello world");


        sign(email, key);
        encrypt(email, key);
        send(email);
    }

    private void sign(String email, String key) {

    }


    public static void main (String args []) {
        new fileSecurity.client.Client().run();
    }
}