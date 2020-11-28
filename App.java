// App.java
package com.github.username;

import java.io.IOException;
import java.net.Inet4Address;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.LinkedList;

import com.sun.jna.Platform;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.TcpPacket.Builder;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.UdpPacket;

public class App {

	private static int udpCounter = 0;
	private static int udpBytes = 0;
	private static int icmpCounter = 0;
	private static int icmpBytes = 0;
	private static int otherCounter = 0;
	private static int otherBytes = 0;

	public static void main(String[] args) throws PcapNativeException, NotOpenException {

		if (args.length != 1) {
			System.out.println("Argument should be only the pcap file name.");
			return;
		}

		System.out.println("Let's start analysis ");
		// New code below here

		final PcapHandle handle;

		try {
			handle = Pcaps.openOffline(args[0]);
		} catch (Exception e) {
			System.out.println("Failed to open pcap file: " + e.getMessage());
			return;
		}

		System.out.println(handle);

		//Effectively to be used as a set with a get operation.
		Map<TCPFlow, TCPFlow> flowMap = new LinkedHashMap<>();

		PacketListener listener = new PacketListener() {
			public void gotPacket(Packet packet) {
				if (packet.get(TcpPacket.class) != null) {

					//Get the necessary packets and headers to extract information
					TcpPacket tcpPacket = packet.get(TcpPacket.class);
					IpV4Packet ipPacket = packet.get(IpV4Packet.class);
					TcpHeader tcpHeader = tcpPacket.getHeader();
					IpV4Header ipHeader = ipPacket.getHeader();

					//Extract the addresses and ports from the headers
					String srcAddr = ipHeader.getSrcAddr().getHostAddress();
					String dstAddr = ipHeader.getDstAddr().getHostAddress();
					int srcPort = tcpHeader.getSrcPort().valueAsInt();
					int dstPort = tcpHeader.getDstPort().valueAsInt();

					//Create the new TCPFlow object with the correct information
					TCPFlow flow = new TCPFlow(srcAddr, srcPort, dstAddr, dstPort);
					if(!flowMap.containsKey(flow)) {
						//If the TCPFlow does not exist (determined by its hash function) then we add it
						//to our set of flows and set the start timestamp
						flowMap.put(flow, flow);
						flow.setStartTimeStamp(handle.getTimestamp().getTime());
					} else {
						//If the flow already exists in our set, we get the correct reference
						flow = flowMap.get(flow);
					}

					//When we encounter the FIN flag, we have completed the flow and need to set the end timestamp
					if(tcpHeader.getFin()) {
						flow.setEndTimeStamp(handle.getTimestamp().getTime());
					}

					flow.addPacket(tcpPacket, packet.length());
					//flow.addBytes(packet.length());
					
				} else if (packet.get(UdpPacket.class) != null) {
					udpCounter++;
					udpBytes += (int) packet.length();
				} else if (packet.get(IcmpV4CommonPacket.class) != null) {
					icmpCounter++;
					icmpBytes += (int) packet.length();
				} else {
					otherCounter++;
					otherBytes += (int) packet.length();
				}

			}
		};

		try {
			handle.loop(-1, listener);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		//PRINT TCP SUMMARY TABLE
		System.out.println("TCP Summary Table");
		for(TCPFlow flow : flowMap.keySet()) {
			System.out.println(flow.asCSV());
		}
		System.out.println();

		//PRINT PROTOCOLS SUMMARY
		System.out.println("Additional Protocols Summary Table");
		System.out.printf("UDP, %d, %d\n", udpCounter, udpBytes);
		System.out.printf("ICMP, %d, %d\n", icmpCounter, icmpBytes);
		System.out.printf("Other, %d, %d\n", otherCounter, otherBytes);

		// Cleanup when complete
		handle.close();
	}
}

/**
 * Class that holds information for a list of packets comprising a TCP flow
 */
class TCPFlow {

	private String srcIP;
	private int srcPort;
	private String destIP;
	private int destPort;

	private int numPackets = 0;
	private int numComplete = 0;
	private int numIncomplete = 0;

	private int totalBytes = 0;
	private int completeBytes = 0;

	private boolean syn = false;
	private boolean fin = false;

	private long startTime = 0;
	private long endTime = 0;

	TCPFlow(String sip, int sport, String dip, int dport) {
		srcIP = sip;
		srcPort = sport;
		destIP = dip;
		destPort = dport;
	}

	/**
	 * Calculates the bandwidth for this TCP flow in Mbps
	 */
	private double getBandwidth() {
		double returnVal = 0.0;
		//Only calculate bandwidth if there's more than two completed packets
		if(numComplete >= 2) {
			double seconds = (endTime - startTime) / 1000000.0;
			returnVal = (completeBytes / 125000.0) / seconds;
		}
		return returnVal;
	}

	public void setStartTimeStamp(long time) {
		startTime = time;
	}

	public void setEndTimeStamp(long time) {
		endTime = time;
	}

	/**
	 * Adds a packet to this flow.
	 * @param packet The TcpPacket portion of the packet
	 * @param totalPacketLength The total length of the overall packet - this is NOT the length of the TcpPacket portion
	 */
	public void addPacket(TcpPacket packet, int totalPacketLength) {
		numPackets++;
		totalBytes += totalPacketLength;

		if(packet.getHeader().getSyn()) {
			syn = true;
		}

		//If a flow has started but not finished, we increment the completed packet count
		//and add to the completed bytes 
		if(syn && !fin) {
			numComplete++;
			completeBytes += totalPacketLength;
		}
		//If the flow is incomplete - that is missing a Syn flag or has received a syn flag but 
		//has yet to receive the fin flag, we increment the number of incomplete packets
		else if(!syn || isComplete()) {
			numIncomplete++;
		}

		if(packet.getHeader().getFin()) {
			fin = true;
		}
	}

	public boolean isComplete() {
		return syn && fin;
	}

	private int getCompletePacketCount() {
		if(isComplete()) {
			return numComplete;
		}
		return 0;
	}

	private int getIncompletePacketCount() {
		if(!isComplete()) {
			return numPackets;
		}

		return numIncomplete;
	}

	/**
	 * Generates a CSV string representing this TCP flow. A TCP CSV is in the form 
	 * srcip, srcport, destip, destport, completed packets, incomplete packets, total bytes, average bandwidth
	 */
	public String asCSV() {
		String base = String.format("%s, %d, %s, %d, %d, %d", 
								srcIP, srcPort, destIP, destPort,
								getCompletePacketCount(), getIncompletePacketCount());
		String bandwidthString = String.format(", %d, %f", totalBytes, getBandwidth());

		if(isComplete()) {
			return base + bandwidthString;
		}

		return base;
	}

	/**
	 * Generates a hash code based off of this TCP Flow's unique ID. The unique ID for a TCP Flow is
	 * a combination of the source IP, source port, destination IP, and destination port.
	 */
	@Override
	public int hashCode() {
		return Objects.hash(srcIP, srcPort, destIP, destPort);
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof TCPFlow 
				&& obj.hashCode() == this.hashCode();
	}
}
