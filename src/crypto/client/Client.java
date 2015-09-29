package crypto.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.json.simple.parser.ParseException;

import client.exception.ServerDHKeyException;
import client.utils.StringParser;
import crypto.messages.ServerMessageType;
import crypto.messages.request.CommDoneRequest;
import crypto.messages.request.DHExDoneRequest;
import crypto.messages.request.DHExRequest;
import crypto.messages.request.DHExStartRequest;
import crypto.messages.request.HelloRequest;
import crypto.messages.request.MessageLengthReceivedRequest;
import crypto.messages.request.NextLengthRequest;
import crypto.messages.request.NextMessageLengthRequest;
import crypto.messages.request.SpecsDoneRequest;
import crypto.messages.request.TextDoneRequest;
import crypto.messages.request.TextReceivedRequest;
import crypto.messages.request.TextRequest;
import crypto.messages.response.CommDoneResponse;
import crypto.messages.response.DHExResponse;
import crypto.messages.response.DHExStartResponse;
import crypto.messages.response.FinishResponse;
import crypto.messages.response.HelloResponse;
import crypto.messages.response.MessageLengthReceivedResponse;
import crypto.messages.response.NextLengthResponse;
import crypto.messages.response.SpecsResponse;
import crypto.messages.response.TextReceivedResponse;
import crypto.messages.response.TextResponse;
import crypto.students.DHEx;
import crypto.students.StreamCipher;

/***
 * Client skeleton class given to the candidates in order to provide a
 * better picture of what is going on here. It also will help you to
 * comprehend the client/server protocol previously to do your 
 * man in the middle server.
 * 
 * @author Pablo Serrano (based on Renlord's code...)
 *
 */
public class Client {
	// for debug and info
	private static Logger log = Logger.getLogger(Client.class);
	
	// network buffer required to send/receive operations
	private final int BUFFER_SIZE = 1024 * 8; // 8 KB must be enough!
	
	// private attributes
	private String ip;
	private int port;
	private String studentId;
	private int counter;
	
	// crypto variables
	private BigInteger generator;
	private BigInteger prime;
	private BigInteger pkClient;
	private BigInteger pkServer;
	private BigInteger skClient;
	private BigInteger sharedKey;
	
	// network variables
	private Socket socket;
	private DataOutputStream writer;
	private DataInputStream reader;
	
	// communication protocol variables
	private long[] linesToWork;
	private BigInteger p1;
	private BigInteger p2;
	private StreamCipher streamCipher;
	private ArrayList<String> corpus;
	
	public Client(String ip, int port, String studentId) {
		// networking variables
		this.ip = ip;
		this.port = port;
		
		// messaging variables
		this.studentId = studentId;
		this.counter = 1;
		
		// corpus
		try {
			corpus = readLines();
		} catch (IOException ioe) {
			// critical error!!!
			log.error("No corpus file!");
			System.exit(-1);
		}
	}

	public void startClient() {
		// This is the sequence of steps in the client...
		try {
			socket = new Socket(ip, port);
			writer = new DataOutputStream(socket.getOutputStream());
			reader = new DataInputStream(socket.getInputStream());
			log.info("Connected to Server...");
			
			log.info("==================== 1) Contact Phase Now ====================");
			contactPhase();
			log.info("==================== 2) Exchange Phase Now ===================");
			exchangePhase();
			log.info("==================== 3) Specification Phase Now ==============");
		    specificationPhase();
		    log.info("==================== 4) Communication Phase Now ==============");
		    communicationPhase();
			exit();
			
		} catch (IOException ioe) {
			log.error("Connection with the server was not possible");
			ioe.printStackTrace();
		} catch (ParseException pe) {
			log.error("The message received was not parsed correctly");
			pe.printStackTrace();
		} catch (ServerDHKeyException keye) {
			log.error(keye.getMessage());
		} finally {
			// just in case that something goes wrong...
			if (socket != null && !socket.isClosed())
				try {
					socket.close();
				} catch (IOException ex) {
					log.warn("Socket was not closed properly. JDK must do it for you...");
				}
		}
	}

	/***
	 * This method starts the negotiation between the client and the server.
	 * It sends a CLIENT_HELLO message and waits until receives a SERVER_HELLO
	 * message.
	 * 
	 * @throws IOException    Communication errors will throw this one
	 * @throws ParseException Appears if something unexpected is received
	 */
	private void contactPhase() throws IOException, ParseException {
		HelloRequest request = new HelloRequest(studentId, ++counter);
		log.debug("Message to send: [" + request.toJSON() + "]");
		writer.write(request.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		byte[] buffer = new byte[BUFFER_SIZE];
		reader.read(buffer);
		String reply = new String(buffer, "UTF-8");
		
		log.debug("Message received: [" + reply + "]");
		HelloResponse response = new HelloResponse();
		response.fromJSON(StringParser.getUTFString(reply));
	}
	
	/***
	 * Method to face the key exchange protocol. Here a basic Diffie-Hellman
	 * protocol is implemented (book version). From the server, client receives
	 * global parameters and client must calculate the shared key.
	 * 
	 * @throws IOException    Communication errors will throw this one
	 * @throws ParseException Appears if something unexpected is received
	 */
	private void exchangePhase() throws IOException, ParseException {
		DHExStartRequest startRequest = new DHExStartRequest(++counter);
		log.debug("Message to send: [" + startRequest.toJSON() + "]");
		writer.write(startRequest.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		// get the public parameters and calculate the shared key
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		
		log.debug("Message received: [" + reply + "]");
		DHExStartResponse response = new DHExStartResponse();
		response.fromJSON(StringParser.getUTFString(reply));
		
		generator = response.getGenerator();
		prime = response.getPrime();
		pkServer = response.getPkServer();
		skClient = response.getSkClient();
		
		// after that the client got the public parameters, it calculates the shared key
		if (skClient != BigInteger.ZERO) {
			BigInteger[] pair = DHEx.createDHPair(generator, prime, skClient);
			pkClient = pair[1];
		} else {
			BigInteger tempKey = DHEx.createPrivateKey(2048);
			BigInteger[] pair = DHEx.createDHPair(generator, prime, tempKey);
			skClient = pair[0];
			pkClient = pair[1];
		}
		
		DHExRequest dhexRequest = new DHExRequest(pkClient, ++counter);
		log.debug("Message to send: [" + dhexRequest.toJSON() + "]");
		writer.write(dhexRequest.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		// calculate the shared key
		buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		reply = new String(buff, "UTF-8");
		
		log.debug("Message received: [" + reply +"]");
		DHExResponse dhResponse = new DHExResponse();
		dhResponse.fromJSON(StringParser.getUTFString(reply));
		
		sharedKey = DHEx.getDHSharedKey(pkServer, skClient, prime);
		log.debug("The shared key is: [" + sharedKey + "]");
		
		// finalize the process sending the shared key (for checking only)
		DHExDoneRequest doneRequest = new DHExDoneRequest(sharedKey, ++counter);
		log.debug("Message to send: [" + doneRequest.toJSON() + "]");
		writer.write(doneRequest.toJSON().getBytes("UTF-8"));
		writer.flush();
	}
	
	/***
	 * Previously to encrypt messages, server and client must agree the amount of
	 * messages they will use. In the specification phase client will receive the 
	 * information needed to encrypt and decrypt server messages.
	 *  
	 * @throws IOException    Communication errors will throw this one
	 * @throws ParseException Appears if something unexpected is received
	 */
	private void specificationPhase() throws IOException, ServerDHKeyException, ParseException {
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		
		// from the message we got the number of lines that will be sent
		log.debug("Message received: [" + reply + "]");
		if (reply.contains("SERVER_DHEX_ERROR"))
			throw new ServerDHKeyException();
		
		SpecsResponse specsResponse = new SpecsResponse();
		specsResponse.fromJSON(StringParser.getUTFString(reply));
		
		linesToWork = specsResponse.getOutLines();
		p1 = specsResponse.getP1();
		p2 = specsResponse.getP2();
	}
	
	/***
	 * All the symmetric encryption and decryption occurs here. Ciphers must be instantiated 
	 * and executing using the derivated keys from p1 and p2. From a text corpus client and 
	 * server interchange some lines, all of them encrypted. The challenge for client is to
	 * decrypt and answer accordingly to server expectations.
	 * 
	 * @throws IOException    Communication errors will throw this one
	 * @throws ParseException Appears if something unexpected is received
	 */
	private void communicationPhase() throws IOException, ParseException {
		// stream cipher is instantiated here!
		streamCipher = new StreamCipher(sharedKey, prime, p1, p2);
		
		// send ACK informing that we are ready to encrypt/decrypt
		SpecsDoneRequest request = new SpecsDoneRequest(++counter);
		log.debug("Message to send: [" + request.toJSON() + "]");
		writer.write(request.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		// Receive all text from Server
		receiveAllLines();
		
		// Reset the Shift Register prior to sending out CLIENT_TEXT messages
		streamCipher.reset();
		
		// Send all text to Server
		sendAllLines();
		
		// Wait for last server message
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		
		log.debug("Message received: [" + reply + "]");
		CommDoneResponse response = new CommDoneResponse();
		response.fromJSON(StringParser.getUTFString(reply));
		
		// answers properly
		CommDoneRequest doneRequest = new CommDoneRequest();
		log.debug("Message to send: [" + doneRequest.toJSON() + "]");
		writer.write(doneRequest.toJSON().getBytes("UTF-8"));
	}
	
	/***
	 * If everything goes well, client must finish the communication properly
	 * with the server.
	 * 
	 * @throws IOException    Communication errors will throw this one
	 * @throws ParseException Appears if something unexpected is received
	 */
	private void exit() throws IOException, ParseException {
		// process the last message...
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		
		log.debug("Message received: [" + reply + "]");
		FinishResponse response = new FinishResponse();
		response.fromJSON(StringParser.getUTFString(reply));
		
		// try to close the socket... 
		log.info("Client Tasks completed successfully. Terminating cleanly...");
		if (socket != null && !socket.isClosed())
			socket.close();
	}
	
	//*******************************************************************************//
	//  Methods for: Receive messages
	//*******************************************************************************//
	private void receiveAllLines() throws IOException, ParseException {
		// let's do this until no more lines are received!
		while (true) {
			if (receiveLine())
				break;
		}
	}
	
	private boolean receiveLine() throws IOException, ParseException {
		long messageLength = 0L, lineNumber = 0L;
		
		// we read the size of the line corpus
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		
		// two possible messages could be received, next length and text done
		// but client also can request some info...
		log.debug("Message received: [" + reply + "]");
		if (reply.contains(ServerMessageType.SERVER_TEXT_DONE.toString()))
			return true;
		else if (reply.contains(ServerMessageType.SERVER_NEXT_LENGTH.toString())) {
			NextLengthResponse response = new NextLengthResponse();
			response.fromJSON(StringParser.getUTFString(reply));
			
			messageLength = response.getLength();
			lineNumber = response.getId();
		} else {
			NextLengthRequest request = new NextLengthRequest(++counter);
			log.debug("Message to send: [" + request.toJSON()+ "]");
			writer.write(request.toJSON().getBytes("UTF-8"));
			writer.flush();
		}
		
		// Send Acknowledgement of Message Length
		MessageLengthReceivedRequest msgACKRequest = null; 
		msgACKRequest = new MessageLengthReceivedRequest(lineNumber, ++counter);
		log.debug("Message to send: [" + msgACKRequest.toJSON() + "]");
		writer.write(msgACKRequest.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		// Get complete TEXT Message			
		TextResponse response = strictReceive(messageLength);
		
		// decrypt the content of the message
		String decryptedBody = decrypt(response.getBody());
		System.out.println("SERVER_TEXT <<<<<<<<<<<< ID: " + response.getId());
		System.out.println("Cipher Text: \n" + response.getBody());
		System.out.println("Plain Text: \n" + decryptedBody);
		
		// Inform Client TEXT Message Received
		TextReceivedRequest request = new TextReceivedRequest(lineNumber, ++counter);
		log.debug("Message to send: [" + request.toJSON() + "]");
		writer.write(request.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		return false;
	}
	
	private TextResponse strictReceive(long length) throws IOException, ParseException {
		TextResponse response = new TextResponse();
		
		byte[] buffer = new byte[(int)length];
		reader.read(buffer);
		String reply = new String(buffer, "UTF-8");
		log.debug("Message received: [" + reply + "]");
		response.fromJSON(StringParser.getUTFString(reply));
		
		return response;
	}
	
	private String decrypt(String ciphertext) {
		return streamCipher.decrypt(ciphertext);
	}
	
	//*******************************************************************************//
	//  Methods for: Send messages
	//*******************************************************************************//
	private void sendAllLines() throws IOException, ParseException {
		for (int i = 0; i < linesToWork.length; i++) {
			log.debug("Line to encrypt: [" + linesToWork[i] + "]");
			sendLine(linesToWork[i], corpus.get((int)linesToWork[i]));
		}
		
		TextDoneRequest request = new TextDoneRequest();
		log.debug("Message to send: [" + request.toJSON() + "]");
		writer.write(request.toJSON().getBytes("UTF-8"));
		writer.flush();
	}
	
	private ArrayList<String> readLines() throws IOException {
		final String PATH = "corpus.txt";
		BufferedReader br = null;
		ArrayList<String> file = null;
		
		try {
			String line;
			br = new BufferedReader(new FileReader(PATH));
			
			while ((line = br.readLine()) != null) {
				if (file == null)
					file = new ArrayList<String>();
				file.add(line);
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
			
			// make the list empty
			if (file != null)
				file.clear();
		} finally {
			if (br != null)
				br.close();
		}
		
		log.debug("Courpus read. Contains [" + file.size() + "] lines");
		return file;
	}
	
	private void sendLine(long id, String line) throws IOException, ParseException {
		String encrpytedMsg = streamCipher.encrypt(line);
		TextRequest msgRequest = new TextRequest(id, encrpytedMsg, ++counter);
		
		// Send TEXT Message Length
		NextMessageLengthRequest lenRequest = new NextMessageLengthRequest(id, msgRequest.toJSON(), ++counter);
		log.debug("Message to send: [" + lenRequest.toJSON() + "]");
		writer.write(lenRequest.toJSON().getBytes("UTF-8"));
		writer.flush();
		
		// Length Acknowledgement
		byte[] buff = new byte[BUFFER_SIZE];
		reader.read(buff);
		String reply = new String(buff, "UTF-8");
		log.debug("Message received: [" + reply + "]");
		
		MessageLengthReceivedResponse lenResponse = new MessageLengthReceivedResponse();
		lenResponse.fromJSON(StringParser.getUTFString(reply));
		
		// Send TEXT Message
        System.out.println("CLIENT_TEXT >>>>>>>>> ID: " + id);
        System.out.println("Plain Text: \n" + line);
        System.out.println("Cipher Text: \n" + encrpytedMsg);
        
        log.debug("Message to send: [" + msgRequest.toJSON() + "]");
        writer.write(msgRequest.toJSON().getBytes("UTF-8"));
        writer.flush();
        
        // Wait Acknowledgement of SERVER_TEXT_RECV
        buff = new byte[BUFFER_SIZE];
        reader.read(buff);
        reply = new String(buff, "UTF-8");
        log.debug("Message received: [" + reply + "]");
        
        TextReceivedResponse txtResponse = new TextReceivedResponse();
        txtResponse.fromJSON(StringParser.getUTFString(reply));
	}
}
