package crypto.messages.request;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class TextRequest extends RequestBase {
	
	private String body;
	public String getBody() {
		return body;
	}
	public void setBody(String body) {
		this.body = body;
	}
	
	private long id;
	public long getId() {
		return id;
	}
	public void setId(long id) {
		this.id = id;
	}
	
	public TextRequest() {
		setType(ClientMessageType.CLIENT_TEXT);
	}
	
	public TextRequest(long line, String text, int n) {		
		setType(ClientMessageType.CLIENT_TEXT);
		setCounter(n);
		setId(line);
		setBody(text);
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("body", getBody());
		object.put("id", getId());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setBody((String)object.get("body"));
		setId((long)object.get("id"));
	}

}
