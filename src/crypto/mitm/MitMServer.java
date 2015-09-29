package crypto.mitm;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.log4j.Logger;

/***
 * This class is an skeleton of a very basic server. It must
 * be extended to offer a Man-in-the-Middle attack.
 * Candidates are prompt to modify it at will. Nevertheless,
 * no external libraries could be used to expand Java capabilities.
 * 
 * @author pabloserrano
 */
public class MitMServer {
	// log for debugging purposes...
	private static Logger log = Logger.getLogger(MitMServer.class);
	
	// class parameters...
	private String ip; // refers to real server
	private int port; // used by MitM and Real server
	private String studentId; // id...
	
	// networking variables
	private ServerSocket serverSocket;
	private Socket socket;
	private DataOutputStream writer;
	private DataInputStream reader;
	
	// message buffer
	private final int BUFFER_SIZE = 8 * 1024; // 8KB is ok...
	
	// class constructor
	public MitMServer(String ip, int port, String studentId) {
		this.ip = ip;
		this.port = port;
		this.studentId = studentId;
	}

	// this method attends just one possible client, other 
	// connections will be discarded (server busy...)
	public void start() throws IOException {
		// Start listening for client's messages
		
		// receive the first message
		
		// start communication with server
		
		// do this until...
		
		// send message to server
		
		// receive message
		
		// send message to client
		
		// receive message from client
		
		// when last message arrives from server...
		
		// stop communication with server
		
		// send last message to client
		
		// stop communication with client
		
	}
}
