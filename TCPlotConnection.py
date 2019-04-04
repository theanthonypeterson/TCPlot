#!/usr/bin/env python2

import dpkt
import os
import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import socket
import collections
from TCPlotUtils import *

	  
# GIVEN: a pcap file, source ip, source port, destination ip,
#   and destination port
# RETURNS: returns an ordered dictionary containing the packets
#   that match the connection. Note that packets in both directions
#   are returned!
def filterBySocket(pcap, srcIP, srcPort, dstIP, dstPort):
	dictionary = collections.OrderedDict()
	for timestamp, buf in pcap:
		forwardDirection = isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort)
		reverseDirection = isReverseDirection(buf, srcIP, srcPort, dstIP, dstPort)
		if forwardDirection or reverseDirection:
			dictionary[timestamp] = buf
	return dictionary

   
# GIVEN: buffer, source and destination IP and ports
# RETURNS: true iff packet is in forward direction
def isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort):
	ethernet = dpkt.ethernet.Ethernet(buf)
	ip = ethernet.data
	tcp = ip.data
	tcpSrcIP = inet_to_str(ip.src)
	tcpDstIP = inet_to_str(ip.dst)
	return srcIP == tcpSrcIP and dstIP == tcpDstIP and srcPort == tcp.sport and dstPort == tcp.dport


# GIVEN: buffer, source and destination IP and ports
# RETURNS: true iff packet is in reverse direction
def isReverseDirection(buf, srcIP, srcPort, dstIP, dstPort):
	ethernet = dpkt.ethernet.Ethernet(buf)
	ip = ethernet.data
	tcp = ip.data
	tcpSrcIP = inet_to_str(ip.src)
	tcpDstIP = inet_to_str(ip.dst)
	return srcIP == tcpDstIP and dstIP == tcpSrcIP and srcPort == tcp.dport and dstPort == tcp.sport


# GIVEN: a pcap file
# RETURNS: the minimum timestap of the given pcap file
# EXAMPLE: minTimestamp(pcap) => 1234567899
def minTimestamp(pcap):
	minTS = -1
	for timestamp, buf in pcap.iteritems():
		if minTS == -1 or minTS > timestamp:
			minTS = timestamp
	return minTS


# GIVEN: a pcap file and connection information
# RETURNS: the minimum forward sequence number
def minForwardSequence(pcap, srcIP, srcPort, dstIP, dstPort):
    minSeq = -1
    for timestamp, buf in pcap.iteritems():
        forward = isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort)
        if forward:
            ethernet = dpkt.ethernet.Ethernet(buf)
            ip = ethernet.data
            tcp = ip.data
            if minSeq == -1 or minSeq > tcp.seq:
                minSeq = tcp.seq
    return minSeq


# GIVEN: a pcap file and connection information
# RETURNS: the maximum forward sequence number
def maxForwardSequence(pcap, srcIP, srcPort, dstIP, dstPort):
    maxSeq = -1
    for timestamp, buf in pcap.iteritems():
        forward = isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort)
        if forward:
            ethernet = dpkt.ethernet.Ethernet(buf)
            ip = ethernet.data
            tcp = ip.data
            if maxSeq < tcp.seq:
                 maxSeq = tcp.seq
    return maxSeq

def highestDataSequence(pcap, srcIP, srcPort, dstIP, dstPort):
    prevTS = -1
    prevSeq = -1
    for timestamp, buf in pcap.iteritems():
        forward = isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort)
        reverse = isReverseDirection(buf, srcIP, srcPort, dstIP, dstPort)
        if forward or reverse:
            ethernet = dpkt.ethernet.Ethernet(buf)
            ip = ethernet.data
            tcp = ip.data
            fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
            syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
            rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
            psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH)!= 0
            ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
            urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
            ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
            cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0
            
            if fin_flag:
                return prevTS, prevSeq
            prevTS = timestamp
            prevSeq = tcp.seq
    return -1, -1


# GIVEN: a pcap file and connection information
# RETURNS: the minimum forward sequence number
def minForwardSequenceAfterTime(pcap, srcIP, srcPort, dstIP, dstPort, startTime):
	minTS = minTimestamp(pcap)
	minSeq = -1
	for timestamp, buf in pcap.iteritems():
		relTS = timestamp-minTS
		if relTS < startTime:
			continue
		forward = isForwardDirection(buf, srcIP, srcPort, dstIP, dstPort)
		reverse = isReverseDirection(buf, srcIP, srcPort, dstIP, dstPort)
		
		ethernet = dpkt.ethernet.Ethernet(buf)
		ip = ethernet.data
		tcp = ip.data
		fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
		syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
		rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
		psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH)!= 0
		ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
		urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
		ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
		cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0

		if forward:
			if minSeq == -1 or minSeq > tcp.seq:
				minSeq = tcp.seq
		elif reverse and ack_flag:
			if minSeq == -1 or minSeq > tcp.ack:
				minSeq = tcp.ack
	return minSeq

def openPcap(filename):
	f = open(filename, "rb")
	pcap = dpkt.pcap.Reader(f)
	return pcap

class TCPlotConnection:

	def __init__(self, pcap, srcIP, srcPort, dstIP, dstPort, useTimeWindow,\
		minTime, maxTime, relativeToTimeFrag, relativeToSeqFrag):
		self.pcap = pcap
		self.srcIP = srcIP
		self.srcPort = srcPort
		self.dstIP = dstIP
		self.dstPort = dstPort
		self.useTimeWindow = useTimeWindow
		self.minTime = minTime
		self.maxTime = maxTime
		self.relativeToTimeFrag = relativeToTimeFrag
		self.relativeToSeqFrag = relativeToSeqFrag

	def segment_timestamps(self):
		return list(map(lambda x: x[0], self.data_segments))

	def segment_sequences(self):
		return list(map(lambda x: x[1], self.data_segments))

	def ack_sequences(self):
		return list(map(lambda x: x[1], self.acks))

	def ack_timestamps(self):
		return list(map(lambda x: x[0], self.acks))

	def retransmission_sequences(self):
		return list(map(lambda x: x[1], self.retransmissions))

	def retransmission_timestamps(self):
		return list(map(lambda x: x[0], self.retransmissions))

	def reset_timestamps(self):
		return list(map(lambda x: x[0], self.resets))

	def reset_sequences(self):
		return list(map(lambda x: x[1], self.resets))

	def get_data_acked(self):
		return list(map(lambda x: x[1], self.data_acked))

	def get_data_acked_timestamps(self):
		return list(map(lambda x: x[0], self.data_acked))

	def get_ack_elapsed(self):
		return list(map(lambda x: x[1], self.ack_elapsed))

	def get_ack_elapsed_timestamps(self):
		return list(map(lambda x: x[0], self.ack_elapsed))

	def avg_ack_rate(self):
		return avg(self.ack_rates_only())

	def ack_rates_only(self):
		ack_rates = []
		for i in range(len(self.data_acked)):
			data = self.data_acked[i][1]
			time = self.ack_elapsed[i][1]
			ack_rates.append(data / (time*1.0))
		return ack_rates

	def getVariable(self, variableName):
		if variableName == "avg_mbps":
			avgMBps = self.averageThroughput/1000000.0
			return formatDecimal(avgMBps, 1)
		elif variableName == "avg_ack_rate_Bps":
			avgAckRateBps = self.avg_ack_rate()
			return formatDecimal(avgAckRateBps, 0)
		return variableName

	def execute(self):

		f = open(self.pcap, "rb")
		pcapData = dpkt.pcap.Reader(f)

		self.data_segments = []     # [timestamp, sequence, payload length]
		self.acks = []              # [timestamp, sequence]
		self.resets = []            # [timestamp, sequence]
		self.retransmissions = []	# [timestamp, sequence]
		self.data_acked = []		# [timestamp, bytes]
		self.ack_elapsed = []		# [timestamps, time (milliseconds)]
		self.ack_rates = []			# [bytes/millisecond]

		# Filter by the given connection parameters
		filteredPcap = filterBySocket(pcapData, self.srcIP, self.srcPort, self.dstIP, self.dstPort)

		# Get Minimum timestamp
		minTS = minTimestamp(filteredPcap)
		maxTS = 0
		minSeq = minForwardSequence(filteredPcap, self.srcIP, self.srcPort, self.dstIP, self.dstPort)
		maxSeq = maxForwardSequence(filteredPcap, self.srcIP, self.srcPort, self.dstIP, self.dstPort)	

		# Get sequence offset if zero-origin
		minSeqAfterMinTime = 0
		if self.relativeToSeqFrag:
			minSeqAfterMinTime = minForwardSequenceAfterTime(filteredPcap, self.srcIP, \
				self.srcPort, self.dstIP, self.dstPort, self.minTime)
			minSeqAfterMinTime = minSeqAfterMinTime-minSeq

		finSeen = False

		prevAckSeq = 0
		prevAckTs = 0

		sentSequences = {}

		# Iterate over packets in filtered pcap
		for timestamp, buf in filteredPcap.iteritems():

			# Parse raw buffer
			ethernet = dpkt.ethernet.Ethernet(buf)
			ip = ethernet.data
			tcp = ip.data
			payload_len = len(tcp.data)

			# Relative timestamp
			relativeTS = timestamp-minTS
			#relativeTS = relativeTS - self.minTime
			if self.useTimeWindow and (not (relativeTS >= self.minTime and self.maxTime >= relativeTS)):
					continue

			if self.relativeToTimeFrag:
				relativeTS = relativeTS-self.minTime

			# Flags to signify whether this packet is in forward or reverse direction
			forward = isForwardDirection(buf, self.srcIP, self.srcPort, self.dstIP, self.dstPort)
			reverse = isReverseDirection(buf, self.srcIP, self.srcPort, self.dstIP, self.dstPort)

			# Decode TCP packet flags
			fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
			syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
			rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
			psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH)!= 0
			ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
			urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
			ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
			cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0

			# Set FIN seen flag
			if fin_flag and not finSeen:
				#print("first FIN was at " + str(relativeTS) + " seconds into connection")
				if len(self.ack_rates) > 1:
					self.ack_rates = self.ack_rates[:-1]
				finSeen = True

			# Data segment data point from sender to receiver
			if forward:
				relSeq = (tcp.seq-minSeq)-minSeqAfterMinTime
				if relSeq in sentSequences:
					self.retransmissions.append([relativeTS, relSeq])
				else:
					sentSequences[relSeq] = True
					self.data_segments.append([relativeTS, relSeq, payload_len])
					maxTS = timestamp
					maxSeq = tcp.seq

			# ACK data point from receiver to sender
			if reverse and ack_flag:
				relAckSeq = (tcp.ack-minSeq)-minSeqAfterMinTime
				self.acks.append([relativeTS, relAckSeq])

				# Measure ACK rate since last ACK
				bytesDiff = relAckSeq-prevAckSeq
				timeDiff = (relativeTS-prevAckTs)

				if not finSeen:
					self.data_acked.append([relativeTS, bytesDiff])
					self.ack_elapsed.append([relativeTS, timeDiff])
					if timeDiff > 0:
						self.ack_rates.append((bytesDiff*1.0)/(timeDiff*1000.0))

				prevAckSeq = relAckSeq
				prevAckTs = relativeTS

		netTime = maxTS-minTS
		netByte = maxSeq-minSeq

		if netTime != 0:
			self.averageThroughput = netByte/netTime
		f.close()

