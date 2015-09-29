package client.exception;

public class ServerDHKeyException extends Exception {

	private static final long serialVersionUID = 1L;

	public ServerDHKeyException() {
		super();
	}
	
	@Override
	public String getMessage() {
		return "You and the server are not sharing the same key!";
	}
}
