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

// class name must match plugin name
@LogstashPlugin(name = "spoof")
public class Spoof implements Output {


    public static final PluginConfigSpec<String> SOURCE_HOST_CONFIG =
            PluginConfigSpec.stringSetting("src_host", "");

    public static final PluginConfigSpec<String> SOURCE_PORT_CONFIG =
    PluginConfigSpec.numSetting("src_port", "");
    
    public static final PluginConfigSpec<String> DESTINATION_HOST_CONFIG =
            PluginConfigSpec.stringSetting("dest_host", "");
    
    public static final PluginConfigSpec<String> DESTINATION_PORT_CONFIG =
            PluginConfigSpec.numSetting("dest_port", "");

    public static final PluginConfigSpec<String> DESTINATION_MAC =
            PluginConfigSpec.stringSetting("dest_mac_address", "");
    
            public static final PluginConfigSpec<String> MESSAGE_CONFIG =
            PluginConfigSpec.stringSetting("message", "");

    private final String id;
    private String prefix;
    private PrintStream printer;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile boolean stopped = false;
    private RawUdpPacketSender sender;
    //   private RawSocket socket;

    // all plugins must provide a constructor that accepts id, Configuration, and Context
    public Spoof(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out);
    }

    Spoof(final String id, final Configuration config, final Context context, OutputStream targetStream) {
        this.id = id;
        sender = new RawUdpPacketSender();
       }

    @Override
    public void output(final Collection<Event> events) {
	    Iterator<Event> z = events.iterator();
        while (z.hasNext() && !stopped) {
            try
            {
                byte[] packet = e.getField("message").getBytes();
                URI destinationURI = URI.create("udp://" + e.getField("dest_host") + ":" e.getField("dest_port"));
                URI sourceURI = URI.create("udp://" + e.getField("src_host") + ":" e.getField("src_port"));
                System.out.println("Sending packets to " + destinationURI.getHost() + " on port " + destinationURI.getPort() + " from spoofed address " + sourceURI.getHost() + "(" + source + ")");
                sender.sendPacket(sourceURI, destinationURI, packet, e.getField("dest_mac_address"));
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
        return Arrays.asList(DESTINATION_HOST_CONFIG, DESTINATION_PORT_CONFIG, SOURCE_HOST_CONFIG, SOURCE_PORT_CONFIG, DESTINATION_MAC_ADDRESS, MESSAGE_CONFIG);
    }

    @Override
    public String getId() {
        return id;
    }
}
