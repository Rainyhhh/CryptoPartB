package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class TextDoneRequest extends RequestBase {
	
	public TextDoneRequest() {
		setType(ClientMessageType.CLIENT_TEXT_DONE);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		// just for message validation
		@SuppressWarnings("unused")
		JSONObject object = (JSONObject)parser.parse(json);
	}

}
