package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class CommDoneRequest extends RequestBase {
	
	public CommDoneRequest() {
		setType(ClientMessageType.CLIENT_COMM_END);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		return object.toJSONString();
	}

	@SuppressWarnings("unused")
	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
	}

}
