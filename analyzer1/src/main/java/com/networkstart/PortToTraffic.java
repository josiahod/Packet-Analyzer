package pseudocode;

import java.util.HashMap;

public class PortToTraffic {
    //Uses port number to determine traffic service
    public static String main(String[] info_table){
        String port_number = info_table.get("Source Port");
        // Hash map of most common services
        HashMap <String, String> port_table = new HashMap<String, String>();
        port_table.put("7", "Echo Service");
        port_table.put("20", "FTP-data");
        port_table.put("21", "FTP");
        port_table.put("22", "SSH-SCP");
        port_table.put("23", "Telnet");
        port_table.put("25", "SMTP");
        port_table.put("53", "DNS");
        port_table.put("69", "TFTP");
        port_table.put("80", "HTTP");
        port_table.put("88", "Kerberos");
        port_table.put("102", "Iso-tsap");
        port_table.put("110", "POP3");
        port_table.put("443", "HTTP over SSL");
        port_table.put("465", "SMTP over TLS/SSL, SSM");
        port_table.put("989", "FTP over SSL");
        port_table.put("990", "FTP over SSL");
        port_table.put("993", "IMAP4 over SSL");
        port_table.put("995", "POP3 over SSL");
        port_table.put("1725", "Steam");
        port_table.put("3074", "XBOX Live");
        port_table.put("3306", "MySQL");
        port_table.put("4664", "Google Desktop");
        port_table.put("6881", "BitTorrent");
        port_table.put("6999", "BitTorrent");
        port_table.put("6970", "Quicktime");

        try{
            if (port_table.containsKey(port_number))
                return port_table.get(port_number);
            else
                return String other = "Unknown Service";
        }
        finally{
            return String other = "error encounter";
        }
        


    }
}
