package crypto.mitm;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.json.simple.parser.ParseException;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

import crypto.args.ArgsMitM;

/***
 * This is the skeleton of a server application enabled to receive connections from
 * a remote client. Remote port is required as an argument, nevertheless
 * is up to you to change the project files in order to provide more functionality.
 * 
 * @author pabloserrano
 *
 */
public class Main {
	
	private static Logger log = Logger.getLogger(Main.class);

	public static void main(String[] args) throws ParseException {
		ArgsMitM mitmArgs = readMitMArguments(args);
		
		log.info("Starting server...");
		try {
			MitMServer serv = new MitMServer(mitmArgs.Ip, mitmArgs.Port, mitmArgs.StudentId);
			serv.start();
		} catch (IOException ioe) {
			log.error("An error has ocurred with the server!");
			ioe.printStackTrace();
		}
		log.info("Server stopped successfuly");
	}
	
	// utility function to parse some elements
	private static ArgsMitM readMitMArguments(String[] args) {
		ArgsMitM options = new ArgsMitM();
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
