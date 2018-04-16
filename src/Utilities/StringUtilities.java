package Utilities;


import java.util.Arrays;

public class StringUtilities {
    public static byte[] extractFirstBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg, 0, n);
    }
    public static byte[] extractLastBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg,msg.length-n , msg.length);
    }    
    public static byte[] concatenateBytes(byte[] a,byte[] b){
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
