package crypto.messages.request;

import java.math.BigInteger;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ClientMessageType;

public class DHExRequest extends RequestBase {
	
	private BigInteger pkClient;

	
	public DHExRequest() {
		setType(ClientMessageType.CLIENT_DHEX);
	}
	
	public DHExRequest(BigInteger pk, int n) {
		setType(ClientMessageType.CLIENT_DHEX);
		setCounter(n);
		this.pkClient = pk;
	}

	public BigInteger getPkClient() {
		return pkClient;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("dh_Yc", pkClient.toString());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		pkClient = new BigInteger((String)object.get("dh_Yc"));
	}

}
