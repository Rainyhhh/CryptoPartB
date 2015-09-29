package crypto.messages.response;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class NextLengthResponse extends ResponseBase {
	
	private long length;
	public long getLength() {
		return length;
	}
	public void setLength(long l) {
		length = l;
	}
	
	private long id;
	public long getId() {
		return id;
	}
	public void setId(long i) {
		id = i;
	}
	
	public NextLengthResponse() {
		setType(ServerMessageType.SERVER_NEXT_LENGTH);
	}
	
	public NextLengthResponse(int n) {
		setType(ServerMessageType.SERVER_NEXT_LENGTH);
		setCounter(n);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("length", getLength());
		object.put("id", getId());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setLength((long)object.get("length"));
		setId((long)object.get("id"));
	}

}
