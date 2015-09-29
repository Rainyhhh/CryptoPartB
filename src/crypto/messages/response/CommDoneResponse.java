package crypto.messages.response;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class CommDoneResponse extends ResponseBase {
	
	private String message;
	public String getMessage() {
		return message;
	}
	public void setMessage(String msg) {
		message = msg;
	}
	
	public CommDoneResponse() {
		setType(ServerMessageType.SERVER_COMM_END);
		setMessage("Thank you for your submission. Attempt logged.");
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("msg", getMessage());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setMessage((String)object.get("msg"));
	}

}
