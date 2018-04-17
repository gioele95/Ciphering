package Test;
import secureChat.Client;
import secureChat.Server;

public class MainTest {
    public static void main(String[] args) {
        Client c = new Client("./test/text.txt","127.0.0.1", 8080);
        Server s = new Server(8080);
        new Thread(s).start();
        new Thread(c).start();
    }    
}
