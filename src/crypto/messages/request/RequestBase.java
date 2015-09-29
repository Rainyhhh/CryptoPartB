package crypto.messages.request;

import org.apache.log4j.Logger;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

/***
 * This class defines the general structure of any request in the system.
 * Do not alter this class. If it's necessary, you can extend any class
 * which is extending this one.
 * 
 * @author pabloserrano
 *
 */
public abstract class RequestBase {
	
	// Logger for all the instances
	protected static final Logger log = Logger.getLogger(RequestBase.class);

	// JSON Parser for all the instances
	protected static final JSONParser parser = new JSONParser();
	
	// Message type
	private ClientMessageType type;
	public ClientMessageType getType() {
		return type;
	}
	public void setType(ClientMessageType t) {
		type = t;
	}
	
	// Message Counter
	private long counter;
	public long getCounter() {
		return counter;
	}
	public void setCounter(long n) {
		counter = n;
	}
	
	// JSON extensions...
	public abstract String toJSON();
	public abstract void fromJSON(String json) throws ParseException;
}
