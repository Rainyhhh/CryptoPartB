package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class DHExStartRequest extends RequestBase {
	
	public DHExStartRequest() {
		setType(ClientMessageType.CLIENT_DHEX_START);
	}
	
	public DHExStartRequest(int n) {
		setType(ClientMessageType.CLIENT_DHEX_START);
		setCounter(n);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
	}

}
