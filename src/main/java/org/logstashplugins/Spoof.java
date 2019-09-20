package org.logstashplugins;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.Output;
import co.elastic.logstash.api.PluginConfigSpec;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;
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
import org.logstash.StringInterpolation;
// class name must match plugin name
@LogstashPlugin(name = "spoof")
public class Spoof implements Output {


    public static final PluginConfigSpec<String> SOURCE_HOST_CONFIG =
            PluginConfigSpec.stringSetting("src_host", "");

    public static final PluginConfigSpec<String> SOURCE_PORT_CONFIG =
            PluginConfigSpec.stringSetting("src_port", "1314");
    
     public static final PluginConfigSpec<String> SOURCE_MAC_CONFIG =
            PluginConfigSpec.stringSetting("src_mac", "");

    public static final PluginConfigSpec<String> DESTINATION_HOST_CONFIG =
            PluginConfigSpec.stringSetting("dest_host", "");
    
    public static final PluginConfigSpec<String> DESTINATION_PORT_CONFIG =
            PluginConfigSpec.stringSetting("dest_port", "514");

    public static final PluginConfigSpec<String> DESTINATION_MAC_CONFIG =
            PluginConfigSpec.stringSetting("dest_mac", "");
    
    public static final PluginConfigSpec<String> MESSAGE_CONFIG =
            PluginConfigSpec.stringSetting("message", "message");

    public static final PluginConfigSpec<String> INTERFACE_CONFIG =
            PluginConfigSpec.stringSetting("interface", "");

    private final String id;
    private String prefix;
    private PrintStream printer;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile boolean stopped = false;
    private RawUdpPacketSender sender;
    //   private RawSocket socket;
    private String message;
    private String dest_host;
    private String dest_port;
    private String dest_mac;
    private String src_host;
    private String src_port;
    private String src_mac;
    // all plugins must provide a constructor that accepts id, Configuration, and Context
    public Spoof(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out);
    }

    Spoof(final String id, final Configuration config, final Context context, OutputStream targetStream) {
        this.id = id;
        sender = new RawUdpPacketSender(config.get(INTERFACE_CONFIG));
	message = config.get(MESSAGE_CONFIG);
	dest_host = config.get(DESTINATION_HOST_CONFIG);
	dest_port = config.get(DESTINATION_PORT_CONFIG);
	dest_mac = config.get(DESTINATION_MAC_CONFIG);
	src_host = config.get(SOURCE_HOST_CONFIG);
	src_port = config.get(SOURCE_PORT_CONFIG);
	src_mac = config.get(SOURCE_MAC_CONFIG);
       }

    @Override
    public void output(final Collection<Event> events) {
	    Iterator<Event> z = events.iterator();
            while (z.hasNext() && !stopped) {
            try
            {
		Event event = z.next();
		System.out.println("Original Result " + ((org.logstash.Event)event).toJson());
		System.out.println("Interpolation Result: " + StringInterpolation.evaluate(event, dest_port));

                String evaluatedMessage = StringInterpolation.evaluate(event, message);
	        String evaluatedDestHost = StringInterpolation.evaluate(event, dest_host);
		int evaluatedDestPort = Integer.parseInt(StringInterpolation.evaluate(event, dest_port));
		String evaluatedDestMAC = StringInterpolation.evaluate(event, dest_mac); 
		String evaluatedSourceHost = StringInterpolation.evaluate(event, src_host);
                int evaluatedSourcePort = Integer.parseInt(StringInterpolation.evaluate(event, src_port));
                String evaluatedSourceMAC = StringInterpolation.evaluate(event,src_mac) == "" ?  RawUdpPacketSender.randomMACAddress() : StringInterpolation.evaluate(event, src_mac);
		byte[] packet = evaluatedMessage.getBytes();
                URI destinationURI = URI.create("udp://" + evaluatedDestHost + ":" + evaluatedDestPort );
                URI sourceURI = URI.create("udp://" + evaluatedSourceHost + ":" + evaluatedSourcePort);
                System.out.println("Sending packets to " + destinationURI.getHost() + "(" + evaluatedDestMAC + ")" + " on port " + destinationURI.getPort() + " from spoofed address " + sourceURI.getHost());
                sender.sendPacket(sourceURI, destinationURI, packet, evaluatedDestMAC, evaluatedSourceMAC);
	    }				
            catch(Exception e)
            {
                e.printStackTrace();         
            }
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
        return Arrays.asList(DESTINATION_HOST_CONFIG, DESTINATION_PORT_CONFIG, DESTINATION_MAC_CONFIG ,SOURCE_HOST_CONFIG, SOURCE_PORT_CONFIG, SOURCE_MAC_CONFIG, MESSAGE_CONFIG, INTERFACE_CONFIG);
    }

    @Override
    public String getId() {
        return id;
    }
}
