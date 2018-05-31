package org.nmap4j.parsers;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import junit.framework.Assert;

import org.junit.Test;
import org.nmap4j.parser.INMapRunHandler;
import org.nmap4j.parser.NMapRunHandlerImpl;
import org.nmap4j.parser.NMapXmlHandler;
import org.nmap4j.parser.events.NMap4JParserEventListener;
import org.nmap4j.parser.events.ParserEvent;
import org.xml.sax.SAXException;

import test.constants.IConstants;

public class NMapXmlHandlerTest implements IConstants {
	
	@Test
	public void basicTest() {
		
		String fileName = "nmap-xml/ms-vscan.xml" ;
	
		INMapRunHandler nmrh = new NMapRunHandlerImpl() ;
		NMapXmlHandler nmxh = new NMapXmlHandler( nmrh ) ;
		
		TestListener listener = new TestListener() ;
		
		NMapXmlHandler.addListener(listener) ;
		
		SAXParserFactory spf = SAXParserFactory.newInstance();
	    try {
	    
	      //get a new instance of parser
	      SAXParser sp = spf.newSAXParser();
	      
	      // get the ms-vscan.xml as a stream
	      InputStream in = getClass().getClassLoader().getResourceAsStream( fileName ) ;
	      
	      //parse the file and also register this class for call backs
	      sp.parse( in, nmxh );
	      
	    }catch(SAXException se) {
	      se.printStackTrace();
	    }catch(ParserConfigurationException pce) {
	      pce.printStackTrace();
	    }catch (IOException ie) {
	      ie.printStackTrace();
	    }
	    
	    System.out.println( "\n\n exec time: " + nmxh.getExecTime() + "ms" ) ;
	}
	
	
	private class TestListener implements NMap4JParserEventListener {
		
//		public static int count = 0 ;

		@Override
		public void parseEventNotification(ParserEvent event) {
			//System.out.println( "source = " + event.getEventSource() ) ;
			if( event.getPayload() == null ) {
				Assert.fail() ;
			}			
		}
		
	}

}
