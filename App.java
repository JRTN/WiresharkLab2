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

		Map<TCPFlow, TCPFlow> flowMap = new LinkedHashMap<>();

		PacketListener listener = new PacketListener() {
			public void gotPacket(Packet packet) {
				if (packet.get(TcpPacket.class) != null) {

					TcpPacket tcpPacket = packet.get(TcpPacket.class);
					IpV4Packet ipPacket = packet.get(IpV4Packet.class);
					TcpHeader tcpHeader = tcpPacket.getHeader();
					IpV4Header ipHeader = ipPacket.getHeader();

					String srcAddr = ipHeader.getSrcAddr().getHostAddress();
					String dstAddr = ipHeader.getDstAddr().getHostAddress();
					int srcPort = tcpHeader.getSrcPort().valueAsInt();
					int dstPort = tcpHeader.getDstPort().valueAsInt();

					TCPFlow flow = new TCPFlow(srcAddr, srcPort, dstAddr, dstPort);
					if(!flowMap.containsKey(flow)) {
						flowMap.put(flow, flow);
						flow.setStartTimeStamp(handle.getTimestamp().getTime());
					} else {
						flow = flowMap.get(flow);
					}

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

class TCPFlow {

	private String srcIP;
	private int srcPort;
	private String destIP;
	private int destPort;

	private int numPackets;
	private int numComplete;
	private int numIncomplete;

	private int totalBytes;
	private int completeBytes;

	private boolean syn = false;
	private boolean fin = false;

	private long startTime;
	private long endTime;

	TCPFlow(String sip, int sport, String dip, int dport) {
		srcIP = sip;
		srcPort = sport;
		destIP = dip;
		destPort = dport;

		numPackets = 0;
		numComplete = 0;
		numIncomplete = 0;
		totalBytes = 0;
		startTime = 0;
		endTime = 0;
	}

	private double getBandwidth() {
		double returnVal = 0.0;
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

	public void addPacket(TcpPacket packet, int totalPacketLength) {
		numPackets++;
		totalBytes += totalPacketLength;

		if(packet.getHeader().getSyn()) {
			setSyn(true);
		}

		if(syn && !fin) {
			numComplete++;
			completeBytes += totalPacketLength;
		} else if(!syn || isComplete()) {
			numIncomplete++;
		}

		if(packet.getHeader().getFin()) {
			setFin(true);
		}
	}

	public void addBytes(int val) {
		totalBytes += val;
	}

	public void setSyn(boolean val) {
		syn = val;
	}

	public void setFin(boolean val) {
		fin = val;
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
