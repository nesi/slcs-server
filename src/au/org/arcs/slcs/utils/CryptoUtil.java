package au.org.arcs.slcs.utils;

import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.HexEncoder;
import org.glite.slcs.SLCSException;
import org.glite.slcs.servlet.CertificateServlet;

public class CryptoUtil {

	private static Log LOG = LogFactory.getLog(CertificateServlet.class);
	
    private static final int AES_KEY_SIZE = 128;

    private static final String ASYMMETRIC_ALGORITHM = "RSA";

    private static final String SYMMETRIC_ALGORITHM = "AES";

    public static final Charset ASCII_CHARSET = Charset.forName("ASCII");

    /** Does encoding work */
    private static HexEncoder encoder = new HexEncoder();

    public CryptoUtil() {
    }

    /**
     * Decodes the given public key from PEM format.
     *
     * @param pemKey
     *            PEM-encoded public key text to decode.
     * @return Public key.
     * @throws IOException
     *             On decoding error.
     */
    public PublicKey decodeKey(final String pemFile) throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        final PEMReader reader = new PEMReader(new FileReader(pemFile));
        final X509CertificateObject key = (X509CertificateObject) reader.readObject();
        if (key != null) {
            return key.getPublicKey();
        } else {
            throw new IOException("Error decoding public key.");
        }
    }

    /**
     * Encrypt a message with given public key using asymmetric algorithm
     *
     * @param message
     *            the message to be encrypted
     * @param pk
     *            the public key used to encrypt the message
     * @return the byte array representation of the encrypted message
     * @throws SLCSException
     */
    public byte[] asymEncrypt(byte[] message, PublicKey pk)
            throws SLCSException {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            result = cipher.doFinal(message);
        } catch (Exception exception) {
            throw new SLCSException("Error encrypting data: "
                    + exception.getMessage(), exception);
        }
        return result;
    }

    /**
     * Encrypt a message with given public key using symmetric algorithm
     *
     * @param message
     *            the message to be encrypted
     * @param pk
     *            the public key used to encrypt the message
     * @return the byte array representation of the encrypted message
     * @throws SLCSException
     */
    public byte[] symEncrypt(byte[] message, SecretKey skey) throws SLCSException {
        byte[] result = null;
        try {
            byte[] key = skey.getEncoded();

            SecretKeySpec skeySpec = new SecretKeySpec(key, SYMMETRIC_ALGORITHM);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            result = cipher.doFinal(message);
        } catch (Exception exception) {
            throw new SLCSException("Error encrypting token data: "
                    + exception.getMessage(), exception);
        }
        return result;
    }

    public HybridEncResult hybridEncrypt(byte[] message, PublicKey pk) throws SLCSException {
        HybridEncResult result = new HybridEncResult();
        try {
            SecretKey sk = genSecretKey(SYMMETRIC_ALGORITHM, AES_KEY_SIZE);
            LOG.debug("AES SessionKey: " + toHexString(sk.getEncoded()));
            byte[] encMessage = symEncrypt(message, sk);
            result.encMessage = encMessage;
            result.encSessionKey = asymEncrypt(sk.getEncoded(), pk);
            LOG.debug("AES Encrypted SessionKey: " + toHexString(result.encSessionKey));
            
        } catch (Exception e) {
            throw new SLCSException("Error encrypting data: " + e.getMessage(), e);
        }
        
        return result;
        
    }
    
    private SecretKey genSecretKey(String algo, int size) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(algo);
        kgen.init(size); // 192 and 256 bits may not be available
        
        // Generate the secret key specs.
        return kgen.generateKey();
    }
    /**
     * Convert an array of strings into a byte array produced by concatenating
     * the byte representation of each string in the default character set.
     *
     * @param input
     *            String to convert
     * @return String characters as bytes.
     */
    public static  String toHexString(final byte[] input, final int offset,
            final int length) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            encoder.encode(input, offset, length, out);
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
        try {
            return out.toString(ASCII_CHARSET.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(
                    "ASCII character set not available.");
        }

    }
    
    public static String toHexString(final byte[] input) {
        return toHexString(input, 0, input.length);
    }

    public static void main(String[] args) throws Exception {
        CryptoUtil helper = new CryptoUtil();
        PublicKey key = helper
                .decodeKey("/home/climbingrose/test/certs/testservice.com.pem");
        System.out.println(key);
        System.out.println(helper.asymEncrypt("Hello World Testing Testing".getBytes(), key));
        SecretKey sk = helper.genSecretKey(SYMMETRIC_ALGORITHM, AES_KEY_SIZE);
        byte[] result = helper.symEncrypt("Hello World".getBytes(), sk);
        System.out.println(helper.toHexString("Hello World".getBytes()));
        System.out.println(sk);
        System.out.println(helper.toHexString(result));
           Cipher cipher = Cipher.getInstance("AES");
           cipher.init(Cipher.DECRYPT_MODE, sk);
        byte[] original = cipher.doFinal(result);
        System.out.println(helper.toHexString(original));
        HybridEncResult r = helper.hybridEncrypt("Hello World".getBytes(), key);
        System.out.println(helper.toHexString(r.encMessage));
    }

    public static class HybridEncResult {
        /**
         * The symmetrically encrypted message
         */
        public byte[] encMessage;

        /**
         * The asymmetrically encrypted session key
         */
        public byte[] encSessionKey;
    }

}
