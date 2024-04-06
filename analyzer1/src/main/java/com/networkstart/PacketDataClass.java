

import java.security.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;


public class PacketDataClass {
    public static void Mainhashmap(){
        //Delaration of a mainHashmap
        HashMap main_HashMap = new HashMap<String, packetData>();
        
        //Method for inputting Data to Mainhashmap
        private static void putToMainHash(packetData Data){
            main_HashMap.put(Data.OBJID, Data);
        }

        //Method for returning filtered Data *based on Protocol for now
        private static packetData returnFilter_by_protocol(String protocol){
            ArrayList filter_result = new ArrayList<PacketData>();
            if (protocol == "UDP" or protocol == "TCP"){
                break;
            } else {
                System.out.println("Unknown input");
                return;
            }
            for (PacketData item: Mainhashmap.values()){
                if (item.OBJ.OBJprotocolType == protocol){
                    filter_result.add(item);
                } else{
                    continue;
                };
            return filter_result;
            }

        }

    }
    public static void packetData(String Timestamp , String srcAddr, String desAddr, String srcPort, String destPort, String protocolType){
        // Accepts arguments as Strings for now
        String OBJTimestamp = Timestamp;
        String OBJsrcAddr = srcAddr;
        String OBJdestAddr = desAddr;
        String OBJsrcPort = srcPort;
        String OBJdestPort = destPort;
        String OBJprotocolType = protocolType;
        
        //Find the service tied to the port
        String OBJservice = PortToTraffic.main(OBJsrcPort);
        
        //Generate ID for the packetData Object; WIP
        String OBJID = "example";
        
        //Method for returning values of the obj currently returns as array
        private static String[] return_packet_info(){
            String[] info = {
                OBJID,
                OBJTimestamp,
                OBJsrcAddr,
                OBJdestAddr,
                OBJsrcPort,
                OBJdestPort,
                OBJprotocolType,
                OBJservice
            };
            return info; 
        };
        
        //Method for printing out object's values
        private static String print_info(){
            System.out.println(OBJID);
            System.out.println(OBJTimestamp);
            System.out.println(OBJsrcAddr);
            System.out.println(OBJdestAddr);
            System.out.println(OBJsrcPort);
            System.out.println(OBJdestPort);
            System.out.println(OBJprotocolType);
            System.out.println(OBJservice);
            
        };
    }
}
