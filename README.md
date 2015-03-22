## Origin 
This project is originally from https://code.google.com/p/replayproxy/ by Armin Buescher.

This fork fixes some bugs & provides more details for usage & installation.

## Summary
replayproxy allows you to "re-live" a HTTP session which has been captured in a .pcap file (e.g. in Wireshark). It parses the HTTP streams, caches them, and starts a HTTP proxy. It then replies to HTTP requests with the matching response from the .pcap, ignoring all other requests.

## Usage
`replayproxy.py [-h] [-H HOST] [-p PORT] [-v[v]] FILENAME`

Arguments:
* `-h|--help`   Show usage information
* `-H HOST`     IP to start the proxy on (DEFAULT: 127.0.0.1)
* `-p PORT`     Port to listen on (DEFAULT: 3128)
* `-v[v]`       Verbose output (DEFAULT: log only ERRORs, -v = INFO, -vv = DEBUG)
* `FILENAME`    Path to the .pcap file to parse (*required*)

Normal usage:
 - obtain a .pcap file containing the captured HTTP session (e.g. using tcpdump or Wireshark)
 - run replayproxy to start the HTTP proxy (see details above)
 - configure your browser to use the proxy settings (IP & port) on which replayproxy is running
 - browse to the site that was captured

To get you started `test.pcap` in this repository contains a capture of a visit to http://www.honeynet.org

## Dependencies and Installation
* Python 2.7+
* dpkt library (http://code.google.com/p/dpkt/)
* pynids library (http://jon.oberheide.org/pynids/)

For detailed installation instructions, see the [INSTALL.md](INSTALL.md) file
