package crypto.messages.response;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class DHExResponse extends ResponseBase {
	
	public DHExResponse() {
		setType(ServerMessageType.SERVER_DHEX_DONE);
	}
	
	public DHExResponse(int n) {
		setType(ServerMessageType.SERVER_DHEX_DONE);
		setCounter(n);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type",getType().toString());
		object.put("n",getCounter());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
	}

}
