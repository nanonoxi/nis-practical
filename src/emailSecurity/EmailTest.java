package emailSecurity;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Created by meradarichter on 2014/03/27
 */
public class EmailTest {

    public static void main(String[] args) {
        Logger LOGGER = Logger.getLogger(Client.class.getName());
        Security.addProvider(new BouncyCastleProvider());

        /*KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            LOGGER.log(Level.INFO, "Key pair generator initialized");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            LOGGER.log(Level.SEVERE, "RSA - No such algorithm");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            LOGGER.log(Level.SEVERE, "BC - No such provider");
        }

        if (keyPairGenerator != null) {
            LOGGER.log(Level.INFO, "Key pair generated");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            LOGGER.log(Level.INFO, "Private " + privateKey);
            LOGGER.log(Level.INFO, "Public " + publicKey);

        }

        final String username = "nano.noxi@gmail.com";
        final String password = "coolBreeze";

        Properties props = new Properties();
        props.put("mail.debug", "true");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("nano.noxi+from@gmail.com"));
            message.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse("nano.noxi+to@gmail.com"));
            message.setSubject("Testing Subject");
            message.setText("Dear Mail Crawler,"
                    + "\n\n No spam to my email, please!");

            Transport.send(message);

            System.out.println("Done");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }*/

        checkProvidersAndJCE();
    }

    public static void checkProvidersAndJCE(){
        final Provider[] providers = Security.getProviders(); for (int i = 0; i < providers.length; i++) {
            final String name = providers[i].getName();
            final double version = providers[i].getVersion();
            System.out.println("Provider[" + i + "]:: " + name + " " + version);
        }
        try {
//Without the unlimited strength policy files
//this results in 128, after they have been installed properly the result is 2147483647.
            System.out.println(Cipher.getMaxAllowedKeyLength("AES"));
        } catch (NoSuchAlgorithmException ex) { Logger.getLogger(EmailTest.class.getName()).log(Level.SEVERE, null, ex);
        } }
}
