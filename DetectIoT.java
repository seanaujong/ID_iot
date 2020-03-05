import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class DetectIoT {

    public static final String PCAP_FILE_NAME = "netLog.txt";
    
    public static final String WHITELIST = "whitelist.txt";

    public static final String SRC_PATTERN = "Ethernet II, Src:";
    
    public static HashMap<String, ArrayList<String>> macAddresses = new HashMap<>();

    public static void main(String[] args) throws IOException, SQLException {
        Scanner pcapScanner = new Scanner(getFile(PCAP_FILE_NAME));

        pcapParse(pcapScanner);
        pcapScanner.close();
        
        printMACAddresses();
        
        createConnection();
        
        writeToFile();
    }
    
    public static void createConnection() throws SQLException {
        Connection con = DriverManager.getConnection("jdbc:mysql://localhost:3306/sys", "root", "root");
        Statement stat = con.createStatement();
    }

    // Returns the name of an existing file to analyze
    public static File getFile(String name) {
        File f = new File(name);
        return f;
    }

    // parses the pcap file into a hashmap
    public static void pcapParse(Scanner pcapScanner) {
        while (pcapScanner.hasNext()) {
            String line = pcapScanner.nextLine();
            if (line.contains(SRC_PATTERN)) {
                String address = getMacAddress(line);
                int delimiter = address.indexOf("_");
                if (delimiter == -1) {
                    // unidentified vendor
                    updateMap("UNKNOWN", address);
                } else {
                    String vendor = address.substring(0, delimiter);
                    String identifier = address.substring(delimiter + 1);
                    updateMap(vendor, identifier);
                }
            }
        }
    }
    
    // update the map of MAC addresses
    public static void updateMap(String key, String val) {
        if (macAddresses.containsKey(key)) {
            ArrayList<String> list = macAddresses.get(key);
            list.add(val);
        } else {
            ArrayList<String> list = new ArrayList<>();
            list.add(val);
            macAddresses.put(key, list);
        }
    }

    // gets the MAC address from the line
    public static String getMacAddress(String line) {
        Scanner lineScanner = new Scanner(line);
        while (lineScanner.hasNext()) {
            String next = lineScanner.next();
            if (next.contains("Src:")) {
                // we found the MAC address!
                String address = lineScanner.next();
                lineScanner.close();
                return address;
            }
        }
        lineScanner.close();
        throw new IllegalArgumentException("line must always contain the MAC address");
    }
    
    // prints out the hashmap
    public static void printMACAddresses() {
        for (String key : macAddresses.keySet()) {
            System.out.println(key);
            System.out.println(macAddresses.get(key));
        }
    }

    // writes to postLog.txt
    public static void writeToFile() throws IOException {
        Desktop desktop = Desktop.getDesktop();
        File log = new File("postLog.txt");
        PrintStream logStream = new PrintStream(log);
        for (String key : macAddresses.keySet()) {
            logStream.println(key);
            logStream.println(macAddresses.get(key));
        }
        desktop.open(log);
        logStream.close();
    }
}
