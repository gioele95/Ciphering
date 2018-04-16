package secureChat;


import Security.Relay;


public class Server extends Relay implements Runnable{
    private int port;  

    public Server(int port){
        this.port = port;       
    }
    public void run() {
        try{
            System.out.println("SERVER RECEIVED: "+new String(noncedReceive("127.0.0.1",8080)));
        }catch(Exception e){
            e.printStackTrace();              
        }
        
    }
    
    
}
