package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class NextLengthRequest extends RequestBase {
	
	private long msgNumber;
	public long getMsgNumber() {
		return msgNumber;
	}
	public void setMsgNumber(long n) {
		msgNumber = n;
	}
	
	public NextLengthRequest() {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH_REQUEST);
	}
	
	public NextLengthRequest(int n) {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH_REQUEST);
		setCounter(n);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("m_n", getMsgNumber());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setMsgNumber((long)object.get("m_n"));
	}

}
