package secureChat;


import Security.Relay;
import java.io.*;


public class Client extends Relay implements Runnable{
    private int port;
    private String myHostName;
    private String msg = null;
    private String file = null;
    public Client(String hostName, int port){
        this.port = port;
        this.myHostName = hostName;   
    }
    public Client(String file, String hostName,int port){
        this(hostName,port);
        this.file = file;
    }  
    public Client(String hostName,int port, String msg){
        this(hostName,port);
        this.msg = msg;
    }
    private boolean readFile() throws Exception{
        StringBuilder sb = new StringBuilder();
        try(BufferedReader br = new BufferedReader(new FileReader(this.file))) {
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }           
        }
        catch(IOException io){
            io.printStackTrace();
            return false;
        }
        this.msg = sb.toString();
        if(this.msg == null)
            throw new Exception("NULL MSG");
        return true;
    }
    public void run() {
        try{
            if(msg==null)
                readFile();
            noncedSend(msg, myHostName, port);
            System.out.println("CLIENT SENT: "+msg);
        }catch(Exception e){
            e.printStackTrace();            
        }
        
    }
    
    
}
