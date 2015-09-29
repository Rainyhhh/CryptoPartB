package crypto.messages.response;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;


public class HelloResponse extends ResponseBase {
	
	public HelloResponse() {
		setType(ServerMessageType.SERVER_HELLO);
	}
	
	public HelloResponse(int n) {
		setType(ServerMessageType.SERVER_HELLO);
		setCounter(n);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", String.valueOf(getCounter()));
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
	}

}
