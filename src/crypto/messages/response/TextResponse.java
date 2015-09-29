package crypto.messages.response;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class TextResponse extends ResponseBase {
	
	private long id;
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	
	private String body;
	public String getBody() {
		return body;
	}
	public void setBody(String text) {
		body = text;
	}
	
	public TextResponse() {
		setType(ServerMessageType.SERVER_TEXT);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("id", getId());
		object.put("body", getBody());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setId((long)object.get("id"));
		setBody((String)object.get("body"));
	}

}
