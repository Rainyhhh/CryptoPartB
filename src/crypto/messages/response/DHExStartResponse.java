package crypto.messages.response;

import java.math.BigInteger;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class DHExStartResponse extends ResponseBase {
	
	private BigInteger generator;
	public BigInteger getGenerator() {
		return generator;
	}
	private BigInteger prime;
	public BigInteger getPrime() {
		return prime;
	}
	private BigInteger pkServer;
	public BigInteger getPkServer() {
		return pkServer;
	}
	private BigInteger skClient; // Optional
	public BigInteger getSkClient() {
		return skClient;
	}
	
	public DHExStartResponse() {
		setType(ServerMessageType.SERVER_DHEX);
		this.generator = BigInteger.ZERO;
		this.prime = BigInteger.ZERO;
		this.pkServer = BigInteger.ZERO;
		this.skClient = BigInteger.ZERO;
	}
	
	public DHExStartResponse(BigInteger g, BigInteger p, BigInteger ys, int n) {
		setType(ServerMessageType.SERVER_DHEX);
		setCounter(n);
		this.generator = g;
		this.prime = p;
		this.pkServer = ys;
		this.skClient = BigInteger.ZERO;
	}
	
	public DHExStartResponse(BigInteger g, BigInteger p, BigInteger ys, 
			BigInteger xs, int n) {
		setType(ServerMessageType.SERVER_DHEX);
		setCounter(n);
		this.generator = g;
		this.prime = p;
		this.pkServer = ys;
		this.skClient = xs;
	}

	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("dh_g", generator.toString());
		object.put("dh_p", prime.toString());
		object.put("dh_Ys", pkServer.toString());
		object.put("dh_Xc", skClient.toString());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		setCounter((long)object.get("n"));
		generator = new BigInteger((String)object.get("dh_g"));
		prime = new BigInteger((String)object.get("dh_p"));
		pkServer = new BigInteger((String)object.get("dh_Ys"));
		if (object.containsKey("dh_Xs"))
			skClient = new BigInteger((String)object.get("dh_Xs"));
	}

}
