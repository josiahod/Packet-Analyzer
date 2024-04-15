package com.networkstart;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.management.monitor.Monitor;

public class SnapShot {
    public static void main(String[] args){
        Map<String, String> Hashexample = new HashMap<>();
        ArrayList<HashMap<String,String>> Arrayexample = new ArrayList<>();

        Hashexample.put("Timestamp:", "4:20:20");
        Hashexample.put("Source IP Address:", "192.0.0.255");
        Hashexample.put("Destination IP Address:", "192.0.0.254");
        Hashexample.put("Protocol:", "UDP");
        Hashexample.put("Protocol Version:", "IPv4");
        Hashexample.put("Source Port:", "81" );
        Hashexample.put("Destination Port:", "81");
        

        Arrayexample.add((HashMap<String, String>) Hashexample); 

        

        HashMap<String, String> i = Arrayexample.get(0);    
        ArrayList<HashMap<String, String>> fromfile = readfile("Test3.txt");
        System.out.println(fromfile);

         //write_to_file(Arrayexample, null);
        //System.out.println("Write Success");


    }
    //Writing currently accepted as Arraylist > HashMap
     public static void write_to_file(ArrayList <HashMap<String, String>> data, String file_name){
         file_name = file_name == null ? "empty string" : file_name;
         System.out.println("Passed file name: "+ file_name);
        
         try{
            
            // Initialize the writer
            FileWriter writer = null;
            switch (file_name) {
                case "empty string":
                    LocalDateTime DateTime = java.time.LocalDateTime.now();
                    writer = new FileWriter("Store Snapshots/" + DateTime + ".txt"); 
                    break;
            
                default:
                    writer = new FileWriter("Store Snapshots/" +file_name +".txt"); 
                    
                    break;
            }

            BufferedWriter BufferedWriter = new BufferedWriter(writer);

            //Signal to Continous Packet Capture to Pause Momentarily
            

            //Begin writing
            BufferedWriter.write("[");
            for (int i = 0; i < data.size(); i++) 
            {   
                BufferedWriter.newLine();
                BufferedWriter.write("PACKETDATASTARTHERE");
                BufferedWriter.newLine();
                for (HashMap.Entry<String, String> entry: (data.get(i)).entrySet())
                {
                    BufferedWriter.write(entry.getKey() + "=" + entry.getValue());
                    BufferedWriter.newLine();
                }
                BufferedWriter.write("PACKETDATAENDHERE");
                BufferedWriter.newLine();
            }
            BufferedWriter.write("]");

            
            //Close writing
            BufferedWriter.close();
            //Signal to Continous Packet Capture to Resume
            
        } catch (IOException exception){
            exception.printStackTrace();
        }
    }
     public static ArrayList<HashMap<String,String>> readfile(String filepath){
        try{
            //Initialize Arraylist-Hashmap
            ArrayList<HashMap<String,String>> ResultArray = new ArrayList<HashMap<String,String>>();
            
            //Initialize File path and scanner
           // File workingFile = new File("Store Snapshots/" + filepath);
           File workingFile = new File(filepath);
            Scanner fileReader = new Scanner(workingFile);
            while (fileReader.hasNextLine()) 
            { //Read until End of File
                String data = fileReader.nextLine();
                if (data.equals("[") ){//Start of Arraylist Reached
                    continue;
                } else if (data.equals("]")){//End of Arraylist Reached
                    break;
                }
                
                if (data.equals("PACKETDATASTARTHERE")){ //If PACKETDATA is FOUND
                    HashMap PacketData = new HashMap<String,String>();
                    while (!(data.equals("PACKETDATAENDHERE"))) { //Read until end of PACKETDATA
                        data = fileReader.nextLine();
                        if(!(data.equals("PACKETDATAENDHERE")))
                        {
                        String[] key_value_pair = data.split("="); //Split the line into the key-value pair
                        PacketData.put(key_value_pair[0], key_value_pair[1]); //Append to Hashmap
                        }
                    }
                    ResultArray.add(PacketData);
                }
                
            
            }
            fileReader.close();
            return ResultArray;

        } catch (FileNotFoundException exception){
            System.out.println("FileNotFoundError Occurred");
            exception.printStackTrace();
        }
        return new ArrayList<HashMap<String,String>>();
    } 
}