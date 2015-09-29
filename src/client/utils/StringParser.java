package client.utils;

import org.apache.log4j.Logger;

/***
 * This small class is used to clean the buffer and extract
 * the proper string to deserialize. Without it, the parser
 * can't get where the UTF-8 string ends and throws a
 * ParseException.
 * 
 * @author pabloserrano
 *
 */
public class StringParser {

	private static Logger log = Logger.getLogger(StringParser.class);
	
	public static String getUTFString(String n) {
		int ending = n.lastIndexOf("}");
		String result = n.substring(0, ending + 1);
		log.debug("The real UTF-8 string is: [" + result + "]");
		return result;
	}
}
