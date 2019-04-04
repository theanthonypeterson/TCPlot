# TCPlot

A simple TCP flow plotter program.

## Dependencies

* Python 2.7
* dpkt
* matplotlib

## Summary

This program allows you to plot one (or more) TCP time-sequence graphs from PCAP files.
This program takes as input a single argument, which is the file path of the configuration file
containing your parameters. The configuration file is in XML format. An example is provided 
in example.xml.

## Configuration

The configuration file is in standard XML format and contains a properties section which includes 
global plot parameters:

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

The _x\_axis\_label_ element represents the parameters for the x-axis. 
The _unit_ attribute represents the unit of the x-axis. Acceptable values
are "s" (seconds) or "ms" (millisconds).

The _zero\_origin_ attribute indicates whether the time shall begin at 0 (zero-origined) or shall be the actual wall-clock
time of the capture.




The configuration file also contains a connections section, including one or more
connections. A connection specifies a single TCP connection that shall be included in the
plot. 

## Authors

* Anthony Peterson
