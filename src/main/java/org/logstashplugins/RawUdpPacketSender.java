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
import java.util.Arrays;
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
    private String _interfaceName;

    public RawUdpPacketSender(String interfaceName) {
        try {
            _interfaceName = interfaceName;
            pcap = createPcap(interfaceName);
            if (pcap == null) {
                System.out.println("Failed to start PCAP");
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to start pcap library.", e);
        }
    }

    public void sendPacket(URI source, URI destination, byte[] packet, String destinationMacAddress, String sourceMacAddress)
            throws IOException {
        int port = destination.getPort();
        InetAddress address = InetAddress.getByName(destination.getHost());
        byte[] destinationAddress = address.getAddress();
        InetAddress sourceAddress = InetAddress.getByName(source.getHost());
        sendPacket(sourceAddress.getAddress(), source.getPort(), destinationAddress, port, packet, getMacAddressBytes(destinationMacAddress), getMacAddressBytes(sourceMacAddress));
    }

    private Pcap createPcap(String deviceName) throws IOException {
        PcapIf device = getPcapDevice(deviceName);
        if (device == null) {
            return null;
        }

        //bugged
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

    private byte[] getMacAddressBytes(String macAddress) {
        try {
            String[] macAddressParts = macAddress.split(":");
            byte[] macAddressBytes = new byte[6];
            for (int i = 0; i < 6; i++) {
                Integer hex = Integer.parseInt(macAddressParts[i], 16);
                macAddressBytes[i] = hex.byteValue();
            }
            return macAddressBytes;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String randomMACAddress() {
        Random rand = new Random();
        byte[] macAddr = new byte[6];
        rand.nextBytes(macAddr);

        macAddr[0] = (byte) (macAddr[0] & (byte) 254);  //zeroing last 2 bytes to make it unicast and locally adminstrated

        StringBuilder sb = new StringBuilder(18);
        for (byte b : macAddr) {

            if (sb.length() > 0)
                sb.append(":");

            sb.append(String.format("%02x", b));
        }


        return sb.toString();
    }

    private PcapIf getPcapDevice(String deviceName) {
        List<PcapIf> allDevs = new ArrayList<PcapIf>();
        StringBuilder errorBuffer = new StringBuilder();
        int r = Pcap.findAllDevs(allDevs, errorBuffer);
        if (r == Pcap.NOT_OK || allDevs.isEmpty()) {
            logger.log(Level.SEVERE, String.format("Can't read list of devices, error is %s",
                    errorBuffer.toString()));
            return null;
        }

        for (PcapIf device : allDevs) {
            //System.out.println("Comparing " + deviceName.toLowerCase() + " with " + device.getName().toLowerCase());
            if (deviceName.toLowerCase().equals(device.getName().toLowerCase())) {
                System.out.println("Selected " + device.getName());
                return device;
            }
        }
        System.out.println("Selected default device " + allDevs.get(0).getName());
        return allDevs.get(0);
    }

    private int getHeaderLength() {
        return 14 + 20 + 8; //Ethernet header + IP v4 header + UDP header
    }

    // https://www.javatips.net/api/diddler-master/src/org/jnetpcap/protocol/network/Ip4.java#
    private void sendPacket(byte[] spoofedSourceAddress, int sourcePort, byte[] destinationAddress, int destinationPort, byte[] data, byte[] destinationMacAddress, byte[] sourceMacAddress)
            throws IOException {
        int mtuSize = 1472;
        int dataLength = data.length;
        int fragment = 0;
        int offset = 0;
        Random r = new Random();
        // https://tools.ietf.org/html/rfc6864
        int id = r.nextInt(65536); 

        while (fragment * mtuSize < dataLength) {
            int remainingData = dataLength - (fragment * mtuSize);
            int bytesToSend = remainingData < mtuSize ? remainingData : mtuSize;
            int packetSize = headerLength + bytesToSend;
            JPacket packet = new JMemoryPacket(packetSize);

            packet.scan(JProtocol.ETHERNET_ID);
            packet.order(ByteOrder.BIG_ENDIAN);
            packet.setUShort(12, 0x0800);
            packet.setUByte(14, 0x40 | 0x05);
            Ethernet ethernet = packet.getHeader(new Ethernet());
            ethernet.source(sourceMacAddress);
            ethernet.destination(destinationMacAddress);
            ethernet.checksum(ethernet.calculateChecksum());
            packet.scan(JProtocol.ETHERNET_ID);
            Ip4 ip4 = packet.getHeader(new Ip4());
            ip4.type(Ip4.Ip4Type.UDP);
            byte[] sourceAddress = spoofedSourceAddress;
            ip4.source(sourceAddress);
            ip4.destination(destinationAddress);
            ip4.length(packetSize - ethernet.size());
            byte[] payload = Arrays.copyOfRange(data, fragment * mtuSize, (fragment * mtuSize) + bytesToSend);

            ip4.ttl(64);
            ip4.flags(remainingData > mtuSize ? 0x1 : 0); //Set to 2 if there are more fragments else set to 0
            ip4.offset(offset / 8);
            packet.scan(JProtocol.ETHERNET_ID);
            ip4.id(id);
            if (fragment == 0) {
                Udp udp = packet.getHeader(new Udp());
                udp.source(sourcePort);
                udp.destination(destinationPort);
                udp.length(packetSize - ethernet.size() - ip4.size());
                udp.checksum(0);
                if (udp == null) {
                    throw new IOException("Failed to get udp header from packet.");
                }

            }
            packet.setByteArray(headerLength, payload);
            ip4.checksum(ip4.calculateChecksum());

            if (pcap.sendPacket(packet) != Pcap.OK) {
                throw new IOException(String.format(
                        "Failed to send UDP packet with error: %s", pcap.getErr()));
            }
            fragment += 1;
            offset += payload.length;
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
