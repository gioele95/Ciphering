


public class Prova {
    public static void main(String[] args) {
        Client c = new Client("127.0.0.1", 8080, "Ciao FedericoRossi");
        Server s = new Server(8080);
        new Thread(s).start();
        new Thread(c).start();

    }
    
}
