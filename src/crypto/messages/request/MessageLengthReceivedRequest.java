package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class MessageLengthReceivedRequest extends RequestBase {
	
	private long id;
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	
	public MessageLengthReceivedRequest() {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH_RECV);
	}
	
	public MessageLengthReceivedRequest(long id, int n) {
		setType(ClientMessageType.CLIENT_NEXT_LENGTH_RECV);
		setCounter(n);
		setId(id);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("id", getId());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setId((long)object.get("id"));
	}

}
