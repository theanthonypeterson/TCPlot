#!/usr/bin/env python2

import __main__ as main
import dpkt
from matplotlib.font_manager import FontProperties
import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import socket
import sys
import collections
from TCPlotConnection import *
from xml.dom import minidom


# Map bytes => metabytes
def mapToMB(s):
	return list(map(lambda x: x/1000000.0, s))

# Map bytes => kilobytes
def mapToKB(s):
	return list(map(lambda x: x/1000.0, s))

# Map bytes => megabits
def mapToMb(s):
	return list(map(lambda x: x*8.0, mapToMB(s)))

# Map bytes => kilobits
def mapToKb(s):
	return list(map(lambda x: x*8.0, mapToKB(s)))

def mapBytesByUnitName(s, u):
	if u == "B":
		return s
	elif u == "MB":
		return mapToMB(s)
	elif u == "KB":
		return mapToKB(s)
	elif u == "Mb":
		return mapToMb(s)
	elif u == "Kb":
		return mapToKb(s)
	return s

def getText(value, connection):
	n = len(value)
	inside = True
	current = ""
	mapping = {}
	for i in xrange(0, n):
		c = value[i]
		if c == '$' and not inside:
			inside = True
		if inside:
			current += c
		if c == '}' and inside:
			inside = False
			m = len(current)
			variableName = current[2:m-1]
			mapping[variableName] = connection.getVariable(variableName)
			current = ""
	valueCopy = str(value)
	for key, val in mapping.iteritems():
		valueCopy = valueCopy.replace("${" + key + "}", val)
	return valueCopy

def main(argv):

	if len(argv) < 2:
		print("To run:  %s [config_xml]" % argv[0])
		print("Example: %s /path/to/config.xml" % argv[0])
		return 1
	
	alignment = {"horizontalalignment": "left", "verticalalignment": "top"}

	xmlFile = argv[1]
	
	xml = minidom.parse(xmlFile)
	properties = xml.getElementsByTagName("properties")[0]
	
	outputFilename = properties.getElementsByTagName("output_filename")[0].firstChild.data
	xAxis = properties.getElementsByTagName("x_axis_label")[0].firstChild.data
	yAxis = properties.getElementsByTagName("y_axis_label")[0].firstChild.data

	# Title
	title = None
	titleFontSize = 12
	titleElements = properties.getElementsByTagName("title")
	if len(titleElements) > 0:
		titleTag = titleElements[0]
		title = titleTag.firstChild.data
		if titleTag.hasAttribute("font_size"):
			titleFontSize = int(titleTag.attributes["font_size"].value)

	# Legend properties
	legend = properties.getElementsByTagName("legend")[0]
	legendFontSize = 12
	if legend.hasAttribute("font_size"):
		legendFontSize = int(legend.attributes["font_size"].value)

	# Default units if none are specified
	xAxisUnit = "s"
	yAxisUnit = "B"
	xAxisLabelFontSize = 12
	yAxisLabelFontSize = 12
	xAxisTickFontSize = 12
	yAxisTickFontSize = 12
	xAxisTicks = None
	yAxisTicks = None

	# Get axis units
	xAxisTag = properties.getElementsByTagName("x_axis_label")[0]
	yAxisTag = properties.getElementsByTagName("y_axis_label")[0]
	
	if xAxisTag.hasAttribute("unit"):
		xAxisUnit = xAxisTag.attributes["unit"].value
	if yAxisTag.hasAttribute("unit"):
		yAxisUnit = yAxisTag.attributes["unit"].value	

	# Axis label font size
	if xAxisTag.hasAttribute("label_font_size"):
		xAxisLabelFontSize = int(xAxisTag.attributes["label_font_size"].value)
	if yAxisTag.hasAttribute("label_font_size"):
		yAxisLabelFontSize = int(yAxisTag.attributes["label_font_size"].value)

	# Axis tick font size
	if xAxisTag.hasAttribute("tick_font_size"):
		xAxisTickFontSize = int(xAxisTag.attributes["tick_font_size"].value)
	if yAxisTag.hasAttribute("tick_font_size"):
		yAxisTickFontSize = int(yAxisTag.attributes["tick_font_size"].value)

	# X & Y Axis ticks
	if xAxisTag.hasAttribute("ticks"):
		xAxisTicks = eval(xAxisTag.attributes["ticks"].value)

	if yAxisTag.hasAttribute("ticks"):
		yAxisTicks = eval(yAxisTag.attributes["ticks"].value)

	# Get whether axis are zero-origin
	timeZeroOrigin = True
	seqZeroOrigin = True

	if xAxisTag.hasAttribute("zero_origin"):
		timeZeroOrigin = xAxisTag.attributes["zero_origin"].value == "True"

	if yAxisTag.hasAttribute("zero_origin"):
		seqZeroOrigin = yAxisTag.attributes["zero_origin"].value == "True"
	
	fix, ax = plt.subplots()
	connections = xml.getElementsByTagName("connection")
	for c in connections:
		captureFilename = c.getElementsByTagName("filename")[0].firstChild.data

		# Parse connection source
		source = c.getElementsByTagName("source")[0]
		srcIP = source.attributes["ip"].value
		srcPort = int(source.attributes["port"].value)

		# Parse connection destination
		destination = c.getElementsByTagName("destination")[0]
		dstIP = destination.attributes["ip"].value
		dstPort = int(destination.attributes["port"].value)

		fromSeconds = -1
		toSeconds = -1

		# Get time tag
		timeTags = c.getElementsByTagName("time")
		if len(timeTags) > 0:
			time = timeTags[0]
			fromSeconds = float(time.attributes["from_seconds"].value)
			toSeconds = float(time.attributes["to_seconds"].value)

		# Parse data segments properties	
		dataSegments = c.getElementsByTagName("data_segments")[0]
		dataSegmentsColor = dataSegments.attributes["color"].value
		dataSegmentsRendered = dataSegments.attributes["rendered"].value == "True"
		dataSegmentsLabel = dataSegments.attributes["label"].value

		# Parse ACKs properties
		acks = c.getElementsByTagName("acks")[0]
		acksColor = acks.attributes["color"].value
		acksRendered = acks.attributes["rendered"].value == "True"
		acksLabel = acks.attributes["label"].value

		# Parse re-transmission properties
		retransmissions = c.getElementsByTagName("retransmissions")[0]
		retransmissionsColor = retransmissions.attributes["color"].value
		retransmissionsRendered = retransmissions.attributes["rendered"].value == "True"
		retransmissionsLabel = retransmissions.attributes["label"].value
	
		# Process the capture file
		times = not (fromSeconds == -1 and toSeconds == -1)	
		connection = TCPlotConnection(captureFilename, srcIP, srcPort, \
			dstIP, dstPort, times, fromSeconds, toSeconds, timeZeroOrigin, seqZeroOrigin)
		connection.execute()

		# Plot data segments
		if dataSegmentsRendered:
			timestamps = connection.segment_timestamps()
			sequences = connection.segment_sequences()

			# DATA time unit conversion
			if xAxisUnit == "ms":
				timestamps = list(map(lambda x: x*1000, timestamps))

			# DATA sequence unit conversion
			sequences = mapBytesByUnitName(sequences, yAxisUnit)	
	
			ax.plot(timestamps, sequences, \
				label=dataSegmentsLabel, \
				color=dataSegmentsColor, \
				marker="o", \
				markersize=1, \
				linestyle="None")

		# Plot ACKs
		if acksRendered:
			timestamps = connection.ack_timestamps()
			sequences = connection.ack_sequences()

			# ACK time unit conversion
			if xAxisUnit == "ms":
				timestamps = list(map(lambda x: x*1000, timestamps))
	
			# ACK sequence unit conversion
			sequences = mapBytesByUnitName(sequences, yAxisUnit)

			ax.step(timestamps, sequences, \
				where="post", \
				label=acksLabel, \
				color=acksColor)

		# Plot retransmission (if any)
		if retransmissionsRendered and len(connection.retransmissions) > 0:
			timestamps = connection.retransmission_timestamps()
			sequences = connection.retransmission_sequences()

			# RETRANSMISSIONS time unit conversion
			if xAxisUnit == "ms":
				timestamps = list(map(lambda x: x*1000, timestamps))

			# RETRANSMISSIONS sequence unit conversion
			sequences = mapBytesByUnitName(sequences, yAxisUnit)

			ax.plot(timestamps, sequences, \
				label=retransmissionsLabel, \
				color=retransmissionsColor, \
				marker="x", \
				markersize=5, \
				linestyle="None")

	ax.ticklabel_format(useOffset=False, style="plain")

	#ax.set_yscale("log")

	# Set title and axis labels
	ax.set_ylabel(yAxis, fontsize=yAxisLabelFontSize)
	ax.set_xlabel(xAxis, fontsize=xAxisLabelFontSize)
	ax.set_title(title, fontsize=titleFontSize)

	# Set tick label sizes
	ax.xaxis.set_tick_params(labelsize=xAxisTickFontSize)
	ax.yaxis.set_tick_params(labelsize=yAxisTickFontSize)

	# Add padding to left because of the
	# large sequence numbers
	#plt.gcf().subplots_adjust(left=0.2)
	legend = plt.legend(fontsize=legendFontSize, markerscale=2)
	legend_frame = legend.get_frame()
	legend_frame.set_edgecolor("black")
	legend_frame.set_linewidth(1.0)

	if xAxisTicks is not None:
		plt.yticks(xAxisTicks)

	if yAxisTicks is not None:
		plt.xticks(yAxisTicks)

	# Save figure to file
	plt.savefig(outputFilename, dpi=300, bbox_inches="tight")
	plt.close()
	return 0


if __name__ == "__main__":
    exit(main(sys.argv))

