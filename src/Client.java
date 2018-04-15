
public class Client extends Relay implements Runnable{
    private int port;
    private String myHostName;
    private String msg;
    

    public Client(String hostName,int port, String msg){
        this.port = port;
        this.myHostName = hostName;
        this.msg = msg;        
    }
    public void run() {
        try{
            noncedSend(msg, myHostName, port);
            System.out.println("CLIENT SENT: "+msg);
        }catch(Exception e){
            e.printStackTrace();            
        }
        
    }
    
    
}
