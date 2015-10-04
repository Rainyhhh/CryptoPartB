package crypto.mitm;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import client.utils.StringParser;
import crypto.messages.request.HelloRequest;
import crypto.messages.response.DHExStartResponse;
import crypto.students.DHEx;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

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
	private Socket client_socket;
	private DataOutputStream writer_to_client;
	private DataInputStream reader_from_client;
	private DataOutputStream writer_to_server;
	private DataInputStream reader_from_server;

	// server related
	BigInteger generator_server;
	BigInteger prime_server;
	BigInteger pkServer_server;
	BigInteger skClient_server;
	BigInteger pkClient_server;

	// client related
	BigInteger generator_client;
	BigInteger prime_client;
	BigInteger pkServer_client;
	BigInteger skServer_client;
	BigInteger pkClient_client;

	private JSONParser parser = new JSONParser();

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
	public void start() throws IOException, ParseException {
		// Start listening for client's messages
		serverSocket = new ServerSocket(port);
		client_socket = serverSocket.accept();
		reader_from_client = new DataInputStream(client_socket.getInputStream());
		writer_to_client = new DataOutputStream(client_socket.getOutputStream());

		byte[] buffer_client_hello = new byte[BUFFER_SIZE];
		reader_from_client.read(buffer_client_hello);
		String helloServer = new String(buffer_client_hello, "UTF-8");
		log.debug("MITM Message received: [" + helloServer + "]");

		socket = new Socket(ip, port);
		writer_to_server = new DataOutputStream(socket.getOutputStream());
		reader_from_server = new DataInputStream(socket.getInputStream());
		log.debug("MITM Message to send: [" + helloServer + "]");
		writer_to_server.write(helloServer.getBytes("UTF-8"));
		writer_to_server.flush();

		byte[] buffer_server_hello = new byte[BUFFER_SIZE];
		reader_from_server.read(buffer_server_hello);
		String reply_from_server = new String(buffer_server_hello, "UTF-8");
		log.debug("MITM Message received: [" + reply_from_server + "]");

		log.debug("MITM Message to send: [" + reply_from_server + "]");
		writer_to_client.write(reply_from_server.getBytes("UTF-8"));
		writer_to_client.flush();

		// exchange key with client

		
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

	private void exchange_with_server_and_client() throws IOException, ParseException {
		byte[] buffer_client_start = new byte[BUFFER_SIZE];
		reader_from_client.read(buffer_client_start);
		String reply = new String(buffer_client_start, "UTF-8");

		log.debug("Message received: [" + reply + "]");
		DHExStartResponse response = new DHExStartResponse();
		response.fromJSON(StringParser.getUTFString(reply));

		generator_server = response.getGenerator();
		prime_server = response.getPrime();
		pkServer_server = response.getPkServer();
		skClient_server = response.getSkClient();

		// after that the man_in_the_middle got the public parameters, it calculates the shared key
		if (skClient_server != BigInteger.ZERO) {
			BigInteger[] pair = DHEx.createDHPair(generator_server, prime_server, skClient_server);
			pkClient_server = pair[1];
		} else {
			BigInteger tempKey = DHEx.createPrivateKey(2048);
			BigInteger[] pair = DHEx.createDHPair(generator_server, prime_server, tempKey);
			skClient_server = pair[0];
			pkClient_server = pair[1];
		}

		// create new public parameters for the real client and send
		generator_client = generator_server;
		prime_client = generator_server;
		skServer_client = DHEx.createPrivateKey(2048);
		BigInteger[] pair2 = DHEx.createDHPair(generator_client, prime_client, skServer_client);
		pkServer_client = pair2[1];
		DHExStartResponse response_to_client = new DHExStartResponse(generator_client, prime_client, pkServer_client, (int)response.getCounter());
		writer_to_client.write(response_to_client.toJSON().getBytes("UTF-8"));



	}
}
