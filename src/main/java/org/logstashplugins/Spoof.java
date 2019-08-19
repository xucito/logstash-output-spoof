package org.logstashplugins;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.Output;
import co.elastic.logstash.api.PluginConfigSpec;
//import org.savarese.vserv.tcpip.IPPacket

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
//import com.savarese.rocksaw.net.RawSocket;
//import static com.savarese.rocksaw.net.RawSocket.PF_INET;
//import static com.savarese.rocksaw.net.RawSocket.getProtocolByName;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import java.net.URI;
import java.util.Arrays;
import java.net.InetAddress;
// class name must match plugin name
@LogstashPlugin(name = "spoof")
public class Spoof implements Output {

    public static final PluginConfigSpec<String> PREFIX_CONFIG =
            PluginConfigSpec.stringSetting("prefix", "");

    public static final PluginConfigSpec<String> DESTINATION_HOST_CONFIG =
            PluginConfigSpec.stringSetting("dest_host", "");

     public static final PluginConfigSpec<String> SOURCE_HOST_CONFIG =
            PluginConfigSpec.stringSetting("src_host", "");
    
      public static final PluginConfigSpec<String> DESTINATION_PORT_CONFIG =
            PluginConfigSpec.numSetting("dest_port", "");

  public static final PluginConfigSpec<String> DESTINATION_MAC =
            PluginConfigSpec.stringSetting("dest_mac_address", "");

    private final String id;
    private String prefix;
    private PrintStream printer;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile boolean stopped = false;
    private RawUdpPacketSender sender;
    private String destination;
    private String source;
    //   private RawSocket socket;

    // all plugins must provide a constructor that accepts id, Configuration, and Context
    public Spoof(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out);
    }

    Spoof(final String id, final Configuration config, final Context context, OutputStream targetStream) {
        // constructors should validate configuration options
        this.id = id;
        prefix = config.get(PREFIX_CONFIG);
	destination = config.get(DESTINATION_CONFIG);
        printer = new PrintStream(targetStream);
	sender = new RawUdpPacketSender();
	source = config.get(SOURCE_CONFIG);
        //socket = new RawSocket();
	//socket.open(6799, PF_INET, getProtocolByName("udp"));
       }

    @Override
    public void output(final Collection<Event> events) {
                      try
		      {
		                      // RawUdpPacketSender sender = new RawUdpPacketSender();
		   	//System.out.println("Sending packets...");		      
		        byte[] packet = "THIS IS A tEST MESSAGE".getBytes();
		        URI destinationURI = URI.create("udp://" + destination);
			//System.out.println("Sending packets to " + destinationURI.getHost() + " on port " + destinationURI.getPort());
			//InetAddress ip = InetAddress.getByName(source);
                        //byte[] sourceBytes = ip.getAddress();
			URI sourceURI = URI.create("udp://"+ source);
			System.out.println("Sending packets to " + destinationURI.getHost() + " on port " + destinationURI.getPort() + " from spoofed address " + sourceURI.getHost() + "(" + source + ")");
			sender.sendPacket(sourceURI, destinationURI, packet,);
	             }				
	              catch(Exception e)
		       {
					     e.printStackTrace();         
					     //      System.out.println(
		       }
	              
	    Iterator<Event> z = events.iterator();
        while (z.hasNext() && !stopped) {
            String s = prefix + z.next();
            printer.println(s);
        }
}

    @Override
    public void stop() {
        stopped = true;
        done.countDown();
    }

    @Override
    public void awaitStop() throws InterruptedException {
        done.await();
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        // should return a list of all configuration options for this plugin
        //return Collections.singletonList(PREFIX_CONFIG);
        return Arrays.asList(DESTINATION_HOST_CONFIG, DESTINATION_PORT_CONFIG, PREFIX_CONFIG, SOURCE_HOST_CONFIG, DESTINATION_MAC_ADDRESS);
    }

    @Override
    public String getId() {
        return id;
    }
}
