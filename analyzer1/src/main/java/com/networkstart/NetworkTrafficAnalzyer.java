package com.networkstart;
import java.io.EOFException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.namednumber.Port;
import org.pcap4j.util.NifSelector;

public class NetworkTrafficAnalzyer extends Thread {

    public static void main(String[] args) {
        PcapNetworkInterface nif = selectNetworkInterface();
        if (nif != null){
            capturePacket(nif);
        }else{
            System.out.println("No network interface selected.");
        }
    }

    public static PcapNetworkInterface selectNetworkInterface() {
        // Declare how long an instance of a packet capture is (in data size; not length!)
      

        PcapNetworkInterface nif = null;

        // Select network interface to capture
        try {
            // List the network devices available with a prompt
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return nif;
    }

    public static void capturePacket(PcapNetworkInterface nif) {

        final int SNAPLEN = 65536; // [bytes]

        // Declare timeout for packet capture
        final int READ_TIMEOUT = 1000; // [ms]

        if (nif == null) { // Early Return if nif is unable to select a device
          System.out.println("There are no devices available");
            return;
        }

        // Start Capture by creating handle
        PcapHandle handle = null;
        try {
            handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e) {
            System.out.println("Unable to create a handle");
            e.printStackTrace();
            return;
        }

        if (handle == null) {
            return;
        }

        
        try {
        for(int i=0; i<=5; i++){
           Packet packet = handle.getNextPacketEx();

           long timestamp = handle.getTimestamp().getTime(); // Using integer value of timestamp

           Date date = new Date(timestamp);
           SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
           String formatTimestamp = dateFormat.format(date);
   
            HashMap<String, String> infoTable = new HashMap<>();
           // Parse Info from Packet
           if (packet.contains(IpV4Packet.class)) {
               IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
   
               TransportPacket transPacket = packet.get(TransportPacket.class);
   
               // Get Source IP Address
               Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
   
               // Get Destination IP Address
               Inet4Address desAddr = ipV4Packet.getHeader().getDstAddr();
   
               // Get Protocol
               byte protocol_type = ipV4Packet.getHeader().getProtocol().value();
   
               String protocolName = getProtocolName(protocol_type);
               // Get Source and Destination Port
               Port srcPort = transPacket.getHeader().getSrcPort();
               Port destPort = transPacket.getHeader().getDstPort();
   
               // Return the information as hashmap/hashtable
   
               infoTable.put("Timestamp", formatTimestamp);
               infoTable.put("Source IP Address:", srcAddr.getHostAddress());
               infoTable.put("Destination IP Address:", desAddr.getHostAddress());
               infoTable.put("Protocol:", protocolName);
               infoTable.put("Source Port:", Integer.toString(srcPort.valueAsInt()));
               infoTable.put("Destination Port:", Integer.toString(destPort.valueAsInt()));
   
   
           } else if (packet.contains(IpV6Packet.class)) {
               // Handle IPv6 packet
               IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
   
               // Get Source IP Address
               Inet6Address srcAddr = ipV6Packet.getHeader().getSrcAddr();
   
               // Get Destination IP Address
               Inet6Address desAddr = ipV6Packet.getHeader().getDstAddr();
               TransportPacket transPacket = packet.get(TransportPacket.class);
               // Get Next Header (Protocol)
               byte nextHeader = ipV6Packet.getHeader().getNextHeader().value();
   
               String protocolName = getProtocolName(nextHeader);
               Port srcPort = transPacket.getHeader().getSrcPort();
               Port destPort = transPacket.getHeader().getDstPort();
               // Return the information as hashmap/hashtable

   
               infoTable.put("Timestamp", formatTimestamp);
               infoTable.put("Source IP Address:", srcAddr.getHostAddress());
               infoTable.put("Destination IP Address:", desAddr.getHostAddress());
               infoTable.put("Protocol:", protocolName);
               infoTable.put("Source Port:", Integer.toString(srcPort.valueAsInt()));
               infoTable.put("Destination Port:", Integer.toString(destPort.valueAsInt()));
   
           } else {
               System.out.println("Packet is neither IPv4 nor IPv6");
               return;
           }
           System.out.println(infoTable);
        }

        } catch (PcapNativeException | TimeoutException | EOFException e) {
            e.printStackTrace();
            return;
        } catch (NotOpenException e) {
            e.printStackTrace();
        }finally{
            handle.close();
        }
    }

        // Get Timestamp of Packet
        // This will be useful for storing chronological data of the packet
 
    
    private static String getProtocolName(byte protocolType) {
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