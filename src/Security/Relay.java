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
    private static final int INTSIZE = 4;
    public static boolean encryptedSend(byte[] data,String hostName,int port) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        byte[] data_bytes = Hash.appendDigest(data);
        byte[] encryptedBytes = Encryption.encrypt(data_bytes);
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
    public static byte[] decryptedReceive(int port) throws NoSuchAlgorithmException, Exception{
        byte [] msg = receive(port);
        byte [] digest_plain = Encryption.decrypt(msg);
        return Hash.checkDigest(digest_plain);
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
}
