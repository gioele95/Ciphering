package Security;


import Utilities.StringUtilities;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Relay {
    private static final int IVSIZE = 16;
    private static final int CHUNKSIZE = 1024;
    private static final int HASHSIZE = 32;
    private static final int INTSIZE = 4;

    private static SecretKey aesKey = null;
    private static SecretKey shaKey = null;
    private static byte[] ivBytes =  null;
    private static int sequenceCounter=0;
    public void generateKey() throws NoSuchAlgorithmException{
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        aesKey = kgen.generateKey();
        kgen = KeyGenerator.getInstance("HmacSHA256");
        shaKey = kgen.generateKey();        
    }
    public IvParameterSpec computeIV(Cipher encryptCipher) throws NoSuchAlgorithmException{
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
    public boolean encryptedSend(byte[] data,String hostName,int port) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        if(aesKey==null)
            generateKey();
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = computeIV(encryptCipher);
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey,ivParams);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
        byte[] data_bytes = appendDigest(data);
        cipherOutputStream.write(data_bytes);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        byte[] encryptedBytes = StringUtilities.concatenateBytes(ivParams.getIV(),outputStream.toByteArray());
        boolean tmp = send(encryptedBytes,hostName,port);
        System.out.println("SENT: "+new String(encryptedBytes));
        return tmp;         
    }
    public static boolean send(byte[] data,String hostName,int port) throws IOException{
        try(Socket ss = new Socket(hostName, port)){
            DataOutputStream ds = new DataOutputStream(ss.getOutputStream());
            ds.writeInt(data.length);
            ds.write(data);         
        }catch(Exception e){
            System.err.println(e.getMessage());
            return false;
        }
        return true;
    }
    public static byte[] receive(int port) throws IOException, Exception{
        try(ServerSocket ss = new ServerSocket(port)){
            Socket s = ss.accept();
            DataInputStream di = new DataInputStream(s.getInputStream());
            int length = di.readInt();
            if(length>0){
                byte[] buffer = new byte[length];
                int read = di.read(buffer);
                ss.close();
                if(read != length ){
                    throw new Exception("communication error");
                }
                return buffer;
            }
        }catch(Exception e){
            System.err.println(e.getMessage());
        }
        return null;
    }
    public byte[] decryptedReceive(int port) throws NoSuchAlgorithmException, Exception{
        if(aesKey==null)
            generateKey();
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte [] msg = receive(port);
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
        byte [] digest_plain = outputStream.toByteArray();
        byte [] digest = StringUtilities.extractFirstBytes(digest_plain, HASHSIZE);
        byte [] plainText = StringUtilities.extractLastBytes(digest_plain, digest_plain.length-HASHSIZE);
        byte [] computedHash = computeDigest(plainText);
        System.out.println("COMPUTED HASH: "+new String(computedHash));
        if(compareDigests(computedHash, digest))
            System.out.println("YOU ARE SAFE TO GO ");
        else
            System.out.println("THEY ARE DIFFERENT, STUDY MORE");
        return plainText;
    }
    public byte[] computeDigest(byte [] msg) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
       Mac mac = Mac.getInstance(shaKey.getAlgorithm());
       mac.init(shaKey);
       return mac.doFinal(msg);
    }
    public byte[] appendDigest(byte[] data) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException{
        byte[] digest = computeDigest(data);
        return StringUtilities.concatenateBytes(digest,data );
    }
    public byte[] noncedReceive(String hostName,int port) throws IOException, Exception{
        byte[] nonce = ByteBuffer.allocate(INTSIZE).putInt(generateNonce()).array();
        send(nonce, hostName, port);
        byte[] msg = decryptedReceive(port); 
        byte[] receivedNonce = StringUtilities.extractLastBytes(msg,INTSIZE);
        if(Arrays.equals(receivedNonce, nonce))
            System.out.println("THE CLIENT IS TRUSTWORTHY");   
        else
            System.out.println("TRUDY IS HERE, REPLAY ATTACK");
        return StringUtilities.extractFirstBytes(msg,msg.length-INTSIZE);
    }
    public boolean noncedSend(String data,String hostName,int port) throws IOException, Exception{
        byte [] nonce = receive(port);
        byte [] msg = data.getBytes();
        msg = StringUtilities.concatenateBytes(msg, nonce);  //NONCE AT THE TAIL
        return encryptedSend(msg, hostName, port);        
    }
    
    public int generateNonce(){
        return (new SecureRandom()).nextInt();
    }
    private boolean compareDigests(byte [] d1, byte [] d2) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException{
        //DIGESTS ARE COMPARED BY COMPARING THEIR HASHES IN ORDER TO AVOID TIMING ATTACKS
        byte [] dd1 = computeDigest(d1);
        byte [] dd2 = computeDigest(d2);
        return Arrays.equals(dd1, dd2);
    }
    
}
