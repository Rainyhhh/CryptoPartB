package crypto.args;

import org.apache.log4j.Logger;
import org.kohsuke.args4j.Option;

/***
 * This bean represents the arguments received by the Server application.
 * Please, refer to args4j for more details and documentation.
 * 
 * Remember to extend this class adding all the additional parameters that
 * you need. 
 * 
 * @author pabloserrano
 *
 */
public class ArgsMitM {
	// private logger for debug only
	private static Logger log = Logger.getLogger(ArgsMitM.class);

	@Option(name="-ip", usage="ip where the real server is located", required=true)
	public String Ip;
	
	@Option(name="-port", usage="port where the real server is listening", required=true)
	public int Port;
	
	@Option(name="-studentId", usage="id required by the server", required=true)
	public String StudentId;
	
	public void showArgs() {
		log.debug("Parameters for ArgsServer class:");
		log.debug("Ip: [" + Ip + "]");
		log.debug("Port: [" + Port + "]");
		log.debug("StudentId: [" + StudentId + "]");
	}
}
