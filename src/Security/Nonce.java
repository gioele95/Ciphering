
package Security;

import Utilities.StringUtilities;
import java.security.SecureRandom;
import java.util.Arrays;

public class Nonce {
    private static final int INTSIZE = 4;       
    public static  int generateNonce(){
        return (new SecureRandom()).nextInt();
    }  
    public static boolean checkNonce(byte[] msg,byte [] nonce){
        byte[] receivedNonce = StringUtilities.extractLastBytes(msg,INTSIZE);
        boolean res = Arrays.equals(receivedNonce, nonce);
        if(res)
            System.out.println("THE CLIENT IS TRUSTWORTHY");   
        else
            System.out.println("TRUDY IS HERE, REPLAY ATTACK");
        return res;
    }
}
