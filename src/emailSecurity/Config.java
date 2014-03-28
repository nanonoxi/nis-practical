package emailSecurity;

/**
 * Created by meradarichter on 2014/03/27
 * For use with Client.java
 *
 * Change this file to set the variables used in the program.
 */
public class Config {

    public static final String USERNAME = "nisuctassignment@gmail.com";
    public static final String PASSWORD = "nis@uct2014";

    public static final String CONTENT = "The quick brown fox jumps over the lazy dog.";
    public static final String SUBJECT = "Hello World";

    public static final String FROM_ADDRESS = "nisuctassignment@gmail.com";
    public static final String TO_ADDRESS_1 = "brndan022@myuct.ac.za";
    public static final String TO_ADDRESS_2 = "nisuctassignment+dan@gmail.com";

    public static final String HOST = "smtp.uct.ac.za";
    public static final String PORT = "25";

    public static final String KEY_LOCATION = "keys/Certificates.p12";
    public static final String KEY_ALIAS = "key from secure.comodo.com";
    public static final String KEY_TYPE = "PKCS12";
    public static final String KEY_PASSWORD = "nis@uct2014";
}
