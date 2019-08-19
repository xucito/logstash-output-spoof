package org.logstashplugins;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.List;
import java.util.Random;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;

public class RawUdpPacketSender {
    private static Logger logger = Logger.getLogger(RawUdpPacketSender.class.getName());

    private Pcap pcap = null;
    private int headerLength = getHeaderLength();
    //private int UDP_SOURCE_PORT = 44226;
    private byte[] sourceMacAddress;

    public RawUdpPacketSender() {
        try {
            pcap = createPcap();
            if(pcap == null)
            {
             System.out.println("Failed to start PCAP");
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to start pcap library.", e);
        }
    }

    public void sendPacket(URI source,URI destination, byte[] packet, String destinationMacAddress)
            throws IOException {
        int port = destination.getPort();
        InetAddress address = InetAddress.getByName(destination.getHost());
        byte[] destinationAddress = address.getAddress();
        InetAddress sourceAddress = InetAddress.getByName(source.getHost());
        sendPacket(sourceAddress.getAddress(), sourceAddress.getPort(),destinationAddress, port, packet, getMacAddressBytes(destinationMacAddress));
    }

    private Pcap createPcap() throws IOException {
        PcapIf device = getPcapDevice();
        if (device == null) {
            return null;
        }
        
	//bugged 
	sourceMacAddress = getMacAddressBytes(randomMACAddress());;//device.getHardwareAddress();  //Use device's MAC address as the source address
        StringBuilder errorBuffer = new StringBuilder();
        int snapLen = 64 * 1024;
        int flags = Pcap.MODE_NON_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snapLen, flags, timeout,
                errorBuffer);
        if (logger.isLoggable(Level.INFO)) {
            logger.info(String.format("Pcap starts for device %s successfully.", device));
	 }
        return pcap;
    }
     
    private byte[] getMacAddressBytes(String macAddress)
    {
	 try {
	  String[] macAddressParts = macAddress.split(":");
byte[] macAddressBytes = new byte[6];
for(int i=0; i<6; i++){
    Integer hex = Integer.parseInt(macAddressParts[i], 16);
    macAddressBytes[i] = hex.byteValue();
}
return macAddressBytes;
     }
    catch(Exception e)
    {
            e.printStackTrace();
            return null;
    }
    }

    private String randomMACAddress(){
    Random rand = new Random();
    byte[] macAddr = new byte[6];
    rand.nextBytes(macAddr);

    macAddr[0] = (byte)(macAddr[0] & (byte)254);  //zeroing last 2 bytes to make it unicast and locally adminstrated

    StringBuilder sb = new StringBuilder(18);
    for(byte b : macAddr){

        if(sb.length() > 0)
            sb.append(":");

        sb.append(String.format("%02x", b));
    }


    return sb.toString();
    }

    private PcapIf getPcapDevice() {
        List<PcapIf> allDevs = new ArrayList<PcapIf>();
        StringBuilder errorBuffer = new StringBuilder();
        int r = Pcap.findAllDevs(allDevs, errorBuffer);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            logger.log(Level.SEVERE, String.format("Can't read list of devices, error is %s",
                    errorBuffer.toString()));
            return null;
        }
        String deviceName = System.getProperty("raw_packet_network_interface", "eth32");
        
	//Delete later
	 for (PcapIf device : allDevs) {
	    System.out.println(device.getName());
        }

	
	
	for (PcapIf device : allDevs) {
            if (deviceName.equals(device.getName())) {
                 System.out.println("Selected " + device.getName());
	         return device;
            }
        }
	System.out.println("Selected default device " + allDevs.get(4).getName());
        return allDevs.get(4);
    }

    private int getHeaderLength() {
        return 14 + 20 + 8; //Ethernet header + IP v4 header + UDP header
    }

    private void sendPacket(byte[] spoofedSourceAddress, int sourcePort, byte[] destinationAddress, int destinationPort, byte[] data, byte[] destinationMacAddress)
            throws IOException {
        int dataLength = data.length;
        int packetSize = headerLength + dataLength;
        JPacket packet = new JMemoryPacket(packetSize);
        packet.order(ByteOrder.BIG_ENDIAN);
        packet.setUShort(12, 0x0800);
        packet.scan(JProtocol.ETHERNET_ID);
        Ethernet ethernet = packet.getHeader(new Ethernet());
        ethernet.source(sourceMacAddress);
        ethernet.destination(destinationMacAddress);
        ethernet.checksum(ethernet.calculateChecksum());

        //IP v4 packet
        packet.setUByte(14, 0x40 | 0x05);
        packet.scan(JProtocol.ETHERNET_ID);
        Ip4 ip4 = packet.getHeader(new Ip4());
        ip4.type(Ip4.Ip4Type.UDP);
        ip4.length(packetSize - ethernet.size());
        byte[] sourceAddress = spoofedSourceAddress;
        ip4.source(sourceAddress);
        ip4.destination(destinationAddress);
        ip4.ttl(64);
        ip4.flags(2); //Sets to DF so that it does not fragment message
        ip4.offset(0);
        ip4.checksum(ip4.calculateChecksum());

        //UDP packet
        packet.scan(JProtocol.ETHERNET_ID);
        Udp udp = packet.getHeader(new Udp());
        udp.source(sourcePort);
        udp.destination(destinationPort);
        udp.length(packetSize - ethernet.size() - ip4.size());
        udp.checksum(udp.calculateChecksum());
        
	packet.setByteArray(headerLength, data);
        packet.scan(Ethernet.ID);

        if (pcap.sendPacket(packet) != Pcap.OK) {
            throw new IOException(String.format(
                    "Failed to send UDP packet with error: %s", pcap.getErr()));
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character
                    .digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
