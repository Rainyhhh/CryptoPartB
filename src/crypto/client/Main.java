package crypto.client;

import org.apache.log4j.Logger;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

import crypto.args.ArgsClient;

/***
 * This is the skeleton of a client application enabled to connect with
 * a remote server. Remote port and IP are provided as arguments, nevertheless
 * is up to you to change the project files in order to provide more functionality.
 * 
 * @author pabloserrano
 *
 */
public class Main {
	
	// log4j logger for debug
	private static Logger log = Logger.getLogger(Main.class);

	public static void main(String[] args) {		
		// parse arguments
		ArgsClient clientArgs = readClientArguments(args);

		// init communication with server
		Client client = new Client(clientArgs.Ip, clientArgs.Port, clientArgs.StudentId);
		client.startClient();
	}
	
	// utility function to parse some elements
	private static ArgsClient readClientArguments(String[] args) {
		ArgsClient options = new ArgsClient();
		CmdLineParser parser = new CmdLineParser(options);
		try {
			parser.parseArgument(args);
			options.showArgs();
		} catch(CmdLineException cle) {
			log.error(cle);
			parser.printUsage(System.err);
			System.exit(-1);
		}
		return options;
	}

}
