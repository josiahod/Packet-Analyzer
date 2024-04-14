package com.networkstart;


import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HashMap;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import java.io.EOFException;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeoutException;
import java.util.ArrayList; 
import java.util.List;
 
import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.namednumber.Port;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.NifSelector;
import java.net.InetAddress;



public class GUI extends Thread {
    private static JFrame mainFrame;
    private static JLabel headerLabel;
    private static JLabel statusLabel;
    private static JPanel controlPanel;
    private static JTable table;
    private static DefaultTableModel tableModel;
    private static TableRowSorter<DefaultTableModel> rowSorter;
    private static JPanel filterPanel; // New panel for the filter
    private static JComboBox<String> filterComboBox; 
    private static List<HashMap<String, String>> packetsList = new ArrayList<>(); //stores each of the packets

 

    //starts gui
    public GUI(){
        prepareGUI();
    }

    public static void main(String[] args){

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
           GUI swingControlDemo = new GUI();      
           swingControlDemo.showTableDemo();
       } catch (IOException e) {
           e.printStackTrace();
       }
       return nif;
   }

   public static  void capturePacket(PcapNetworkInterface nif) {

       final int SNAPLEN = 65536; // [bytes]

       // Declare timeout for packet capture
       final int READ_TIMEOUT = 15000; // [ms]

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
       for(int i=0; i<70; i++){
          Packet packet = handle.getNextPacketEx();

          long timestamp = handle.getTimestamp().getTime(); // Using integer value of timestamp

          Date date = new Date(timestamp);
          SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss:SSS");
          String formatTimestamp = dateFormat.format(date);
  
           HashMap<String, String> infoTable = new HashMap<>();
           try {
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
                infoTable.put("Source IP Address", srcAddr.getHostAddress());
                infoTable.put("Destination IP Address", desAddr.getHostAddress());
                infoTable.put("Protocol", protocolName);
                infoTable.put("Source Port", Integer.toString(srcPort.valueAsInt()));
                infoTable.put("Destination Port", Integer.toString(destPort.valueAsInt()));

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
                infoTable.put("Source IP Address", srcAddr.getHostAddress());
                infoTable.put("Destination IP Address", desAddr.getHostAddress());
                infoTable.put("Protocol", protocolName);
                infoTable.put("Source Port", Integer.toString(srcPort.valueAsInt()));
                infoTable.put("Destination Port", Integer.toString(destPort.valueAsInt()));
            } else if (packet.contains(IcmpV4CommonPacket.class)) {
                infoTable.put("Timestamp", formatTimestamp);
                infoTable.put("Timestamp", formatTimestamp);
                infoTable.put("Source IP Address", "-");
                infoTable.put("Destination IP Address", "-");
                infoTable.put("Protocol", "ICMP");
                infoTable.put("Source Port", "-");
                infoTable.put("Destination Port", "-");
            } else if (packet.contains(IcmpV6CommonPacket.class)) {
                IcmpV6CommonPacket icmpV6Packet = packet.get(IcmpV6CommonPacket.class);
            } else if (packet.contains(ArpPacket.class)) {
                ArpPacket arpPacket = packet.get(ArpPacket.class);
                InetAddress srcAddr = arpPacket.getHeader().getSrcProtocolAddr();
                InetAddress desAddr = arpPacket.getHeader().getDstProtocolAddr();
                infoTable.put("Timestamp", formatTimestamp);
                infoTable.put("Source IP Address", srcAddr.getHostAddress());
                infoTable.put("Destination IP Address", desAddr.getHostAddress());
                infoTable.put("Protocol", "ARP");
                infoTable.put("Source Port", "-");
                infoTable.put("Destination Port", "-");

            } else if (packet.contains(DnsPacket.class)) {
                // Handle DNS packet
                DnsPacket dnsPacket = packet.get(DnsPacket.class);
                IpPacket.IpHeader ipHeader = packet.get(IpPacket.class).getHeader();
                InetAddress srcAddr = ipHeader.getSrcAddr();
                InetAddress desAddr = ipHeader.getDstAddr();
                infoTable.put("Timestamp", formatTimestamp);
                infoTable.put("Source IP Address", srcAddr.getHostAddress());
                infoTable.put("Destination IP Address", desAddr.getHostAddress());
                infoTable.put("Protocol", "DNS");
                infoTable.put("Source Port", "-"); // No source port for DNS (UDP)
                infoTable.put("Destination Port", "-"); // No destination port for DNS (UDP)

            } else {
                throw new IllegalArgumentException("Packet is neither IPv4 nor IPv6");
                // System.out.println("Packet is neither IPv4 nor IPv6");
                // return;
            }

            System.out.println(infoTable);
            addDataToTable(infoTable);
            packetsList.add(infoTable);
        } catch (NullPointerException e) {
            System.out.println("Null Pointer Exception: " + e.getMessage());
            continue; // Move to the next iteration of the loop
        }
        catch (IllegalArgumentException e)
        {
         System.out.println(e.getMessage());
         continue; // Move to the next iteration of the loop
        }
       }

       } catch (PcapNativeException | TimeoutException | EOFException e) {
           e.printStackTrace();
           return;
       } catch (NotOpenException e) {
           e.printStackTrace();
       }
       finally{
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

    private static void prepareGUI(){
        mainFrame = new JFrame("Packet Capture");
        mainFrame.setSize(700,325); //gui window
        mainFrame.setLayout(new GridLayout(3, 1)); 

        mainFrame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent windowEvent){
                System.exit(0);
            }        
        });    

        headerLabel = new JLabel("", JLabel.CENTER); //title

        filterPanel = new JPanel();//panel for filtering our data
        filterPanel.setLayout(new FlowLayout());

        filterComboBox = new JComboBox<>(new String[]{"TCP", "UDP", "ARP", "DNS"}); //dropdown section
        filterComboBox.addActionListener(new ActionListener() //check if dropdown is selected
        {
            public void actionPerformed(ActionEvent e) 
            {
                tableModel.setRowCount(0);
                System.out.println("Protocol Selected: " + filterComboBox.getSelectedItem());
                for (int i = 0; i < packetsList.size(); i++) 
                {
                    HashMap<String, String> packetsTable = packetsList.get(i);
                    if(packetsTable.get("Protocol").equals(filterComboBox.getSelectedItem()))
                    {
                        System.out.println(packetsTable);
                        addDataToTable(packetsTable);
                    }
                    
                }
            }
        });

        filterPanel.add(new JLabel("Protocol:"));
        filterPanel.add(filterComboBox);



        controlPanel = new JPanel(); //packet data stored here
        controlPanel.setLayout(new BorderLayout());

        mainFrame.add(headerLabel, BorderLayout.NORTH);
        mainFrame.add(filterPanel, BorderLayout.CENTER);
        mainFrame.add(controlPanel, BorderLayout.SOUTH); // add control panel at the bottom
        mainFrame.setVisible(true);  
    }

    private static void showTableDemo()
    {
        headerLabel.setText("Packet Capturing"); 

        String[] columnNames = {"Timestamp", "Source IP Address", "Destination IP Address", "Source Port", "Destination Port", "Protocol"};

        tableModel = new DefaultTableModel(columnNames, 0);
        
        table = new JTable(tableModel);
        rowSorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(rowSorter);


        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);
        scrollPane.setPreferredSize(new Dimension(450, 450));

        controlPanel.setLayout(new BorderLayout());
        controlPanel.add(scrollPane, BorderLayout.CENTER);

        mainFrame.setVisible(true);   
    }

    // Method to add a new row of data to the table cntaining our packet data 
    public static void addDataToTable(HashMap<String, String> rowData) 
    {
        Object[] row = new Object[table.getColumnCount()];
        for (int i = 0; i < table.getColumnCount(); i++) {
            row[i] = rowData.get(table.getColumnName(i));
        }
        tableModel.addRow(row);
    }
}
