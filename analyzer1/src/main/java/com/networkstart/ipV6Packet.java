package com.networkstart;
import java.io.EOFException;
import java.io.IOException;
import java.net.Inet6Address;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.namednumber.Port;
import org.pcap4j.util.NifSelector;
import java.util.Date;
import org.pcap4j.packet.IpV6Packet;

public class ipV6Packet extends Thread{
       public static HashMap<String, String> captureIPV6Packet() {
        // Declare how long an instance of a packet capture is (in data size; not length!)
        final int SNAPLEN = 65536; // [bytes]

        //Declare timeout for packet capture
        final int READ_TIMEOUT = 1000; // [ms]

        PcapNetworkInterface nif = null;

        // Select network interface to capture
        try {
            // List the network devices available with a prompt
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        if (nif == null) { // Early Return if nif is unable to select a device
            return null;
        }

        // Start Capture by creating handle
        PcapHandle handle = null;
        try {
            handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e) {
            e.printStackTrace();
            return null;
        }

        if (handle == null) {
            return null;
        }

        Packet packet = null;
        try {
            packet = handle.getNextPacketEx();
        } catch (PcapNativeException | TimeoutException | EOFException e) {
            e.printStackTrace();
            return null;
        }catch(NotOpenException e){
            e.printStackTrace();
            handle.close();
            return null;
        }
       


        // Get Timestamp of Packet
        // This will be useful for storing chronological data of the packet
        long timestamp = handle.getTimestamp().getTime(); // Using integer value of timestamp

        Date date = new Date(timestamp);
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String formatTimestamp = dateFormat.format(date);
        handle.close();

        // Parse Info from Packet
        IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
        if (ipV6Packet == null) {
            System.out.println("Not an IPv4 packet");
            return null;
        }
        TransportPacket transPacket = packet.get(TransportPacket.class);

        // Get Source IP Address
        Inet6Address srcAddr = ipV6Packet.getHeader().getSrcAddr();

        // Get Destination IP Address
        Inet6Address desAddr = ipV6Packet.getHeader().getDstAddr();

        // Get Protocol
        byte protocol_type = ipV6Packet.getHeader().getProtocol().value();

        String protocolName = getProtocolName(protocol_type);
        System.out.println(protocol_type);
        // Get Source and Destination Port
        Port srcPort = transPacket.getHeader().getSrcPort();
        Port destPort = transPacket.getHeader().getDstPort();

        
        // Return the information as hashmap/hashtable
        HashMap<String, String> infoTable = new HashMap<>();

        infoTable.put("Timestamp", formatTimestamp);
        infoTable.put("Source IP Address:", srcAddr.getHostAddress());
        infoTable.put("Destination IP Address:", desAddr.getHostAddress());
        infoTable.put("Protocol:", protocolName);
        infoTable.put("Source Port:", Integer.toString(srcPort.valueAsInt()));
        infoTable.put("Destination Port:", Integer.toString(destPort.valueAsInt()));

        System.out.println(infoTable);

        return infoTable;
        }
    

    private static String getProtocolName(byte protocolType){
        switch (protocolType) {
            case 6:
                return "TCP";
            case 17:
                return "UDP";
            default:
                return "Other";
        }
    }


    
}
