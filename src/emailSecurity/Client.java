package emailSecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Strings;

/**
 * @author Daniel Burnham-King
 * @author Merada Richter
 * 2014/03/26
 *
 * Program for email security: a message from the user is signed and encrypted before being sent off to the receiver.
 *
 * Resources:
 *     https://blogs.oracle.com/javajungle/entry/secure_email_from_java (Mark Heckler)
 *     http://java2s.com/Open-Source/Java/Security/Bouncy-Castle/org/bouncycastle/mail/smime/examples/SendSignedAndEncryptedMail.java.html
 */
public class Client {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private void run() {
        try {
            /** create command map for Bouncy Castle provider */
            MailcapCommandMap commandMap = (MailcapCommandMap) CommandMap.getDefaultCommandMap();

            commandMap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
            commandMap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
            commandMap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
            commandMap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
            commandMap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

            CommandMap.setDefaultCommandMap(commandMap);

            /** create a new session for the user */
            System.out.println("Creating a session for USER=\"" + Config.USERNAME + "\" with PASSWORD=\"" + Config.PASSWORD + "\"" +
                    "\n    using HOST=\"" + Config.HOST + "\" and PORT=" + Config.PORT);

            Properties properties = new Properties();
            //properties.put("mail.debug", "true");
            properties.put("mail.smtp.auth", "true");
            properties.put("mail.smtp.starttls.enable", "true");
            properties.put("mail.smtp.host", Config.HOST);
            properties.put("mail.smtp.port", Config.PORT);

            Session session = Session.getInstance(properties,
                    new javax.mail.Authenticator() {
                        protected PasswordAuthentication getPasswordAuthentication() {
                            return new PasswordAuthentication(Config.USERNAME, Config.PASSWORD);
                        }
                    });

            System.out.println("Creating email FROM=\"" + Config.FROM_ADDRESS + "\" TO=\"" + Config.TO_ADDRESS_1 + "\" and \"" + Config.TO_ADDRESS_2 + "\"" +
                    "\n    with SUBJECT=\"" + Config.SUBJECT + "\"" +
                    "\n    and CONTENT=\"" + Config.CONTENT + "\"");

            MimeMessage body = new MimeMessage(session);
            body.setFrom(new InternetAddress(Config.FROM_ADDRESS));
            InternetAddress[] addresses = {new InternetAddress((Config.TO_ADDRESS_1)), new InternetAddress(Config.TO_ADDRESS_2)};
            body.setRecipients(Message.RecipientType.TO, addresses);
            body.setSubject(Config.SUBJECT);
            body.setContent(Config.CONTENT, "text/plain");
            body.saveChanges();

            /** create and initialize keystore */
            KeyStore keystore = KeyStore.getInstance(Config.KEY_TYPE);

            System.out.println("Loading keys from LOCATION=" + Config.KEY_LOCATION);
            keystore.load(new FileInputStream(Config.KEY_LOCATION), Config.KEY_PASSWORD.toCharArray());

            PrivateKey privateKey = (PrivateKey)keystore.getKey(Config.KEY_ALIAS, Config.KEY_PASSWORD.toCharArray());
            Certificate certificate = keystore.getCertificate(Config.KEY_ALIAS);

            /** create SMIMESignedGenerator */
            SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
            capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
            capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
            capabilities.addCapability(SMIMECapability.dES_CBC);
            capabilities.addCapability(SMIMECapability.aES256_CBC);

            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
                    new IssuerAndSerialNumber(
                            new X500Name(((X509Certificate) certificate).getIssuerDN().getName()),
                                    ((X509Certificate) certificate).getSerialNumber())));
            attributes.add(new SMIMECapabilitiesAttribute(capabilities));

            /** sign email */
            System.out.println("Initializing SMIMESignedGenerator with ALG=SHA1withRSA");
            SMIMESignedGenerator signer = new SMIMESignedGenerator();
            signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                    .build("SHA1withRSA", privateKey, (X509Certificate) certificate));

            ArrayList<Certificate> certificates = new ArrayList<Certificate>();
            certificates.add(certificate);
            signer.addCertificates(new JcaCertStore(certificates));

            System.out.println("Signing email ...");
            MimeMultipart smimeSigned = signer.generate(body);
            MimeMessage signedMessage = new MimeMessage(session);
            Enumeration headers = body.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                signedMessage.addHeaderLine((String) headers.nextElement());
            }

            // Set the content of the signed message
            signedMessage.setContent(smimeSigned);
            signedMessage.saveChanges();

            /** encrypt email */
            System.out.println("Initializaing SMIMEEnvelopedGenerator with BC Provider");
            Certificate recipientCertificate = certificate;
            SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
            encrypter.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator((X509Certificate) recipientCertificate).setProvider("BC"));

            MimeBodyPart smimeEncrypted = encrypter.generate(signedMessage, new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC, 40).setProvider("BC").build());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assert smimeEncrypted != null;
            smimeEncrypted.writeTo(out);

            System.out.println("Encrypting email ...");
            MimeMessage encryptedMessage = new MimeMessage(session, new ByteArrayInputStream(out.toByteArray()));
            headers = body.getAllHeaderLines();
            while (headers.hasMoreElements())
            {
                String headerLine = (String)headers.nextElement();
                // don't override content & headers from original message
                if (!Strings.toLowerCase(headerLine).startsWith("content-"))
                {
                    assert encryptedMessage != null;
                    encryptedMessage.addHeaderLine(headerLine);
                }
            }

            /** send email */
            System.out.println("Sending signed and encrypted mail TO=\"" + Config.TO_ADDRESS_1 + "\" and \"" + Config.TO_ADDRESS_2 + "\"");
            Transport.send(encryptedMessage);

            // for testing
            //System.out.println("Sending signed mail to \"" + Config.TO_ADDRESS_1 + "\" and \"" + Config.TO_ADDRESS_2 + "\"");
            //Transport.send(signedMessage);

            System.out.println("Done.");

        } catch (MessagingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (SMIMEException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }
    }

    public static void main (String args []) {
        (new Client()).run();
    }
}