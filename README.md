# TCPlot

A simple TCP flow plotter program.

## Dependencies

* Python 2.7
* dpkt
* matplotlib

## How to run

```
./TCPlot.py example.xml
```

## Summary

This program allows you to plot one (or more) TCP time-sequence graphs from PCAP files.
This program takes as input a single argument, which is the file path of the configuration file
containing your parameters. The configuration file is in XML format. An example is provided 
in example.xml.

## Configuration

The configuration file is in standard XML format and contains a properties section which includes 
global plot parameters and a set of TCP connection parameters. Please see example.xml for an example.

```xml
<title font_size="INTEGER">STRING</title>
```

The _title_ element represents the title which will be displayed above the plot. A font size of
the title may be specified.

```xml
<output_filename>STRING</output_filename>
```

The _output\_filename_ element represents the destination file name of the output plot file. This
can be a PDF, PNG, JPEG, etc.

```xml
<x_axis_label 
   unit="STRING" 
   zero_origin="BOOLEAN" 
   label_font_size="INTEGER" 
   tick_font_size="INTEGER"
   label="STRING" />
```

The _x\_axis\_label_ element represents the parameters for the x-axis. 
The _unit_ attribute represents the unit of the x-axis. Acceptable values
are "s" (seconds) or "ms" (millisconds).

The _zero\_origin_ attribute indicates whether the time shall begin at 0 (zero-origined) or shall be the actual wall-clock
time of the capture.

The _label\_font\_size_ attribute represents the font size of the x-axis label.
The _tick\_font\_size_ attribute represents the font size of the tick marks used on the x-axis.
The _label_ attribute represents the label of the x-axis.

The same applies for the y-axis, just replace _x\_axis\_label_ with _y\_axis\_label_.

```xml
<legend font_size="INTEGER" rendered="BOOLEAN"/>
```

The _legend_ element represents the legend parameters.
The _font\_size_ attribute represents the font size of the legend text.
The _rendered_ attribute indicates whether to show the legend or not.

The configuration file also contains a _connections_ section, including one or more
connections. A _connection_ element specifies a single TCP connection that shall be included in the
plot. 

```xml
<filename>STRING</filename>
```

The _filename_ element represents the file name of the packet capture containing the connection you wish to plot.

```xml
<source ip="STRING" port="INTEGER"/>
```

The _source_ element represents the connection source parameters of the connection.
The _ip_ attribute represents the IPv4 source address and the _port_ attribute represents the source port.

```xml
<destination ip="STRING" port="INTEGER"/>
```

The _destination_ element represents the connection destination parameters of the connection.
The _ip_ attribute represents the IPv4 destination address and the _port_ attribute represents the destination port.

```xml
<time from_seconds="INTEGER" to_seconds="INTEGER"/>
```

The _time_ element represents the time window from the connection you wish to plot.
The _from\_seconds_ and _to\_seconds\_ attributes represent the start and end times that you wish to plot.
These values depend on whether your plot is set to zero-origined.

```xml
<data_segments color="STRING" rendered="BOOLEAN" label="STRING"/>
```

The _data\_segments_ element represents the properties for the data segments that appear in the plot.
The _color_ attribute represents the color of the data segments.
The _rendered_ attribute indicates whether to show the data segments for this connection.
The _label_ attribute represents the label of the data segments which will appear in the legend.

```xml
<acks color="STRING" rendered="BOOLEAN" label="STRING"/>
```

The _acks_ element represents the properties for the acknowledgment packets.
The same semantics from the _data\_segments_ element apply to the _acks_ element.

```xml
<retransmissions color="STRING" rendered="BOOLEAN" label="STRING"/>
```

The _retransmissions_ element represents the properties for the retransmitted packets.
The same semantics from the _data\_segments_ and _acks_ elements apply to the _retransmissions_ element.

## Future features

* Duplicate acknowledgment markers
* Plot the receive window

## Authors

* Anthony Peterson
