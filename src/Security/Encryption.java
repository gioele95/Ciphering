/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Security;

import static Security.Relay.receive;
import static Security.Relay.send;
import Utilities.StringUtilities;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

/**
 *
 * @author Gioele
 */
public class Encryption{
    private static SecretKey aesKey = null;
    private static byte[] ivBytes =  null;
    private static int sequenceCounter = 0;
    private static final int INTSIZE = 4;
    private static final int IVSIZE = 16;
    private static final int CHUNKSIZE = 1024;



    public static void generateKey() throws NoSuchAlgorithmException{
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        aesKey = kgen.generateKey();        
    }
    public static byte[] encrypt(byte [] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IOException {
        if(aesKey==null)
            generateKey();
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = computeIV(encryptCipher);
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey,ivParams);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        cipherOutputStream.write(data);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        return StringUtilities.concatenateBytes(ivParams.getIV(),outputStream.toByteArray());
    }
    public static IvParameterSpec computeIV(Cipher encryptCipher) throws NoSuchAlgorithmException{
        IvParameterSpec ivParams=null;
        if(sequenceCounter==0){
            SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] iv = new byte[encryptCipher.getBlockSize()];
            randomSecureRandom.nextBytes(iv);
            ivParams = new IvParameterSpec(iv);
            sequenceCounter = ByteBuffer.wrap(ivParams.getIV()).getInt();
        }else{
            sequenceCounter++;
            ivParams = new IvParameterSpec(ByteBuffer.allocate(INTSIZE).putInt(sequenceCounter).array());                 
        }
        return ivParams; 
    }
    public static byte[] decrypt(byte [] msg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IOException{
        if(aesKey==null)
            generateKey();
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");   
        System.out.println("RECEIVED: "+  new String(msg));
        byte iv[] = StringUtilities.extractFirstBytes(msg,IVSIZE);    //EXTRACT THE PLAIN IV THAT IS IN THE HEAD
        byte [] buffer = StringUtilities.extractLastBytes(msg, msg.length-IVSIZE); //MAC + MSG
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(buffer);
        CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
        byte[] buf = new byte[CHUNKSIZE];                              //DECRYPTS AT A RATE OF CHUNKS OF 1024 BYTES
        int bytesRead;
        while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
            outputStream.write(buf, 0, bytesRead);
        }
        return outputStream.toByteArray();
    }
    
}
