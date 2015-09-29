package crypto.messages.response;

import java.math.BigInteger;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import crypto.messages.ServerMessageType;

public class SpecsResponse extends ResponseBase {
	
	private long[] outLines;
	public long[] getOutLines() {
		return outLines;
	}
	public void setOutLines(long[] lines) {
		outLines = lines;
	}
	
	private BigInteger p1;
	public BigInteger getP1() {
		return p1;
	}
	public void setP1(BigInteger p) {
		p1 = p;
	}
	
	private BigInteger p2;
	public BigInteger getP2() {
		return p2;
	}
	public void setP2(BigInteger q) {
		p2 = q;
	}

	public SpecsResponse() {
		setType(ServerMessageType.SERVER_SPEC);
	}
	
	public SpecsResponse(int n) {
		setType(ServerMessageType.SERVER_SPEC);
		setCounter(n);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public String toJSON() {
		JSONObject object = new JSONObject();
		object.put("type", getType().toString());
		object.put("n", getCounter());
		object.put("out_lines", getOutLines());
		object.put("p1", getP1());
		object.put("p2", getP2());
		return object.toJSONString();
	}

	@Override
	public void fromJSON(String json) throws ParseException {
		JSONObject object = (JSONObject)parser.parse(json);
		// normal input
		setCounter((long)object.get("n"));
		setP1(new BigInteger((String)object.get("p1")));
		setP2(new BigInteger((String)object.get("p2")));
		// array of numbers
		JSONArray array = (JSONArray)object.get("out_lines");
		long[] numbers = new long[array.size()];
		for (int i = 0; i < array.size(); i++)
			numbers[i] = (long)array.get(i);
		setOutLines(numbers);
	}

}
