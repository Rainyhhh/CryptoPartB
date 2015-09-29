package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class HelloRequest extends RequestBase {
	
	private String id;
	public String getId() {
		return id;
	}
	private final String part = "one";
	
	public HelloRequest() {
		setType(ClientMessageType.CLIENT_HELLO);
	}
	
	public HelloRequest(String id, long n) {
		setType(ClientMessageType.CLIENT_HELLO);
		setCounter(n);
		this.id = id;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("id", id);
		object.put("n", getCounter());
		object.put("part", part);
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject obj = (JSONObject)parser.parse(json);
		id = (String)obj.get("id");
		setCounter((long)obj.get("n"));	
	}

}
