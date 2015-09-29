package crypto.messages.request;

import java.math.BigInteger;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class DHExDoneRequest extends RequestBase {
	
	private BigInteger sharedKey;
	public BigInteger getSharedKey() {
		return sharedKey;
	}
	public void setSharedKey(BigInteger key) {
		sharedKey = key;
	}
	
	public DHExDoneRequest() {
		setType(ClientMessageType.CLIENT_DHEX_DONE);
	}
	
	public DHExDoneRequest(BigInteger key, int n) {
		setType(ClientMessageType.CLIENT_DHEX_DONE);
		setCounter(n);
		sharedKey = key;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("dh_key", getSharedKey());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		setSharedKey(new BigInteger((String)object.get("dh_key")));
	}

}
