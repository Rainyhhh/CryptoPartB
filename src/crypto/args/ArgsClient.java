package crypto.args;

import org.apache.log4j.Logger;
import org.kohsuke.args4j.Option;

/***
 * This bean represents the arguments received by the Client application.
 * Please, refer to args4j for more details and documentation.
 * 
 * Remember to extend this class adding all the additional parameters that
 * you need. 
 * 
 * @author pabloserrano
 *
 */
public class ArgsClient {
	// private logger for debug only
	private static Logger log = Logger.getLogger(ArgsClient.class);
	
	@Option(name="-ip", usage="indicates the remote ip where the client will be connected", required=true)
	public String Ip;
	
	@Option(name="-port", usage="port that will be reached at the moment of establish the connection with the server", required=true)
	public int Port;
	
	@Option(name="-studentId", usage="informs to the server your student Id for validation purposes", required=true)
	public String StudentId;
	
	public void showArgs() {
		log.debug("Parameters for ArgsClient are:");
		log.debug("IP: [" + Ip + "]");
		log.debug("Port: [" + Port + "]");
		log.debug("StudenId: [" + StudentId + "]");
	}
}
