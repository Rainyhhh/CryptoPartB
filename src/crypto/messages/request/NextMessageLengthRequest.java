package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class NextMessageLengthRequest extends RequestBase {
	
	private long id;
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	
	private long length;
	public long getLength() {
		return length;
	}
	public void setLength(long len) {
		length = len;
	}
	
	public NextMessageLengthRequest() {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH);
	}
	
	public NextMessageLengthRequest(long id, String msg, int n) {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH);
		setCounter(n);
		setId(id);
		setLength(msg.length());
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("id", getId());
		object.put("length", getLength());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setId((long)object.get("id"));
		setLength((long)object.get("length"));
	}

}
