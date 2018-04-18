package Security;

import Utilities.StringUtilities;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Hash {
    private static SecretKey shaKey = null;
    private static final int HASHSIZE = 32;
    public static void generateKey() throws NoSuchAlgorithmException{
        KeyGenerator kgen = KeyGenerator.getInstance("HmacSHA256");
        shaKey = kgen.generateKey();        
    }

    public static byte[] appendDigest(byte[] data) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
        byte[] digest = computeDigest(data);
        return StringUtilities.concatenateBytes(digest,data );
    }
    public static byte[] computeDigest(byte [] msg) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
       if(shaKey==null)
           generateKey();
       Mac mac = Mac.getInstance(shaKey.getAlgorithm());
       mac.init(shaKey);
       return mac.doFinal(msg);
    }
    public static byte[] checkDigest(byte [] digest_plain) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
        byte [] digest = StringUtilities.extractFirstBytes(digest_plain, HASHSIZE);
        byte [] plainText = StringUtilities.extractLastBytes(digest_plain, digest_plain.length-HASHSIZE);
        byte [] computedHash = computeDigest(plainText);
        System.out.println("COMPUTED HASH: "+new String(computedHash));
        if(!compareDigests(computedHash, digest)){
            System.out.println("THEY ARE DIFFERENT, STUDY MORE");
            return null;
        }
        System.out.println("YOU ARE SAFE TO GO ");
        return plainText;
    }
    private static boolean compareDigests(byte [] d1, byte [] d2) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException{
        //DIGESTS ARE COMPARED BY COMPARING THEIR HASHES IN ORDER TO AVOID TIMING ATTACKS
        byte [] dd1 = computeDigest(d1);
        byte [] dd2 = computeDigest(d2);
        return Arrays.equals(dd1, dd2);
    }
    
}
