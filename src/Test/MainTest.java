package Test;
import secureChat.Client;
import secureChat.Server;
public class MainTest {
    private  static final int PORT = 8080;
    private static final String clientIP = "127.0.0.1";
    public static void main(String[] args) {
        Client c = new Client("./test/text.txt",clientIP, PORT);
        Server s = new Server(PORT);
        new Thread(s).start();
        new Thread(c).start();
    }    
}
