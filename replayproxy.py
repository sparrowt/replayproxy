#!/usr/bin/python

###################################################################################################
#
# Copyright (c) 2011, Armin Buescher (armin.buescher@googlemail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
###################################################################################################
#
# File:     replayproxy.py
# Desc.:    ReplayProxy is a forensic tool to replay web-based attacks (and also general HTTP traffic) that were captured in a pcap file.
#           Functionality:
#           * parse HTTP streams from .pcap files
#           * open a TCP socket and listen as a HTTP proxy using the extracted HTTP responses as a cache while refusing all requests for unknown URLs
# Author:   Armin Buescher (armin.buescher@googlemail.com)
# Contribs: Marco Cova (marco@lastline.com), Tom Sparrow (sparrowt@gmail.com)
# Thx to:   Andrew Brampton (brampton@gmail.com) for his example code on how to parse HTTP streams from .pcap files using dpkg
#
###################################################################################################
#
# Changelog
# 1.1 (Marco Cova, marco@lastline.com)
#   - tcpreassembly via pynids
#   - initial support for non-exact matches
#   - general refactoring
#
# 1.2 (Tom Sparrow, sparrowt@gmail.com)
#   - fix handling of missing content-length header
#   - handle request/response parse errors and continue
#
###################################################################################################

import argparse
import dpkt
import gzip
import logging
import nids
import sys
import urlparse
import SocketServer
import StringIO

END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

# { full url: [response1] }
# for now just assume only 1 response per url
resources = {}


########################
# pcap parsing
########################

# keep track of non-closed TCP streams, which otherwise are not processed
# using the regular pynids API
openstreams = {}


def reassembleTcpStream(tcp):

    if tcp.nids_state == nids.NIDS_JUST_EST:
        # always assume it is HTTP traffic (else: if dport === 80)
        tcp.client.collect = 1
        tcp.server.collect = 1

        openstreams[tcp.addr] = tcp
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)

        openstreams[tcp.addr] = tcp
    elif tcp.nids_state in END_STATES:
        del openstreams[tcp.addr]

        processTcpStream(tcp)
    else:
        print >>sys.stderr, "Unknown nids state"


def processTcpStream(tcp):
        ((src, sport), (dst, dport)) = tcp.addr

        # We can not handle HTTPS
        if 443 in [sport, dport]:
            logging.warning("Ignoring HTTPS/SSL stream (%s:%s -> %s:%s)" % (src, sport, dst, dport))
            return

        # data to server
        server_data = tcp.server.data[:tcp.server.count]
        # data to client
        client_data = tcp.client.data[:tcp.client.count]

        # extract *all* the requests in this stream
        req = ""
        while len(req) < len(server_data):
            req_parsed = False
            try:
                req = dpkt.http.Request(server_data)
                req_parsed = True
                host_hdr = req.headers['host']
                full_uri = req.uri if req.uri.startswith("http://") else \
                    "http://%s:%d%s" % (host_hdr, dport, req.uri) if dport != 80 else \
                    "http://%s%s" % (host_hdr, req.uri)
                logging.info("Processing tcp stream for %s", full_uri)
                res = dpkt.http.Response(client_data)
                logging.debug(res)
                if "content-length" in res.headers:
                    body_len = int(res.headers["content-length"])
                    hdr_len = client_data.find('\r\n\r\n')
                    client_data = client_data[body_len + hdr_len + 4:]
                else:
                    hdr_len = client_data.find('\r\n\r\n')
                    body_len = client_data[hdr_len:].find("HTTP/1")
                    client_data = client_data[hdr_len + body_len:]

                if not full_uri in resources:
                    resources[full_uri] = []
                resources[full_uri].append(res)

                server_data = server_data[len(req):]
            except Exception as ex:
                logging.error("Failed to parse {}. Exception: {}".format("response" if req_parsed else "request", str(ex)))
                logging.error("Stopping processing of TCP stream %s:%s -> %s:%s (%s)" % (src, sport, dst, dport, full_uri))
                break


def get_resource(uri):
    # exact match?
    if uri in resources:
        return resources[uri][0]

    resources_by_domain = {}
    for u in resources:
        domain = urlparse.urlparse(u).hostname
        if not domain in resources_by_domain:
            resources_by_domain[domain] = []
        resources_by_domain[domain].append(u)

    uri_domain = urlparse.urlparse(uri).hostname
    uri_path = urlparse.urlparse(uri).path
    if uri_domain in resources_by_domain:
        # do we have one page from the same domain of the requested uri?
        if len(resources_by_domain[uri_domain]) == 1:
            logging.info("Matching %s with %s (one url from requested domain)", uri, resources_by_domain[uri_domain][0])
            return resources[resources_by_domain[uri_domain][0]][0]

        # is there a page with same path as requested uri?
        for u in resources_by_domain[uri_domain]:
            if urlparse.urlparse(u).path == uri_path:
                logging.info("Matching %s with %s (same path and domain)", uri, u)
                return resources[u][0]

    return None


########################
# HTTP proxy
########################
class ProxyServer(SocketServer.TCPServer):
    allow_reuse_address = True


class ProxyRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):
    # handles a request of a client
    # callback for SocketServer
        sock_client = self.request
        http_req = ProxyRequestHandler.recvRequest(sock_client)
        if http_req:
            resp = get_resource(http_req.uri)
            if resp:
                logging.info("Request for %s" % http_req.uri)
                ProxyRequestHandler.sendResponse(resp, sock_client)
            else:
                sock_client.send('')
                logging.warning("Request for unknown URL %s" % http_req.uri)
        sock_client.close()

    @staticmethod
    def recvRequest(sock):
        total_data = data = sock.recv(16384)
        while 1:
            try:
                http_req = dpkt.http.Request(total_data)
                return http_req
            except dpkt.NeedData:
                data = sock.recv(16384)
                total_data += data
                pass
            except:
                "Error while processing HTTP Request!"
                return None

    @staticmethod
    def sendResponse(resp, conn):
        resp.version = '1.0'
        if 'content-encoding' in resp.headers and resp.headers['content-encoding'] == 'gzip':
            del resp.headers['content-encoding']
            compressed = resp.body
            compressedstream = StringIO.StringIO(compressed)
            gzipper = gzip.GzipFile(fileobj=compressedstream)
            data = gzipper.read()
            resp.body = data
        resp.headers['content-length'] = len(resp.body)
        conn.send(resp.pack())


########################
# main
########################

def main():

    # parse args
    argparser = argparse.ArgumentParser()
    argparser.add_argument('PCAP', help='Path to the .pcap file to parse')
    argparser.add_argument('-H', metavar='HOST', default='127.0.0.1', help='Address to listen on (DEFAULT: 127.0.0.1)')
    argparser.add_argument('-p', metavar='PORT', type=int, default=3128, help='Port to listen on (DEFAULT: 3128)')
    argparser.add_argument('-v', action='append_const', const=1, default=[], help='Increase the verbosity level')
    args = argparser.parse_args()

    HOST, PORT = args.H, args.p
    verbosity = len(args.v)

    # setup logger
    if verbosity == 0:
        log_level = logging.ERROR
    elif verbosity == 1:
        log_level = logging.INFO
    else:
        log_level = logging.DEBUG
    logging.basicConfig(format='%(levelname)s:%(message)s', level=log_level)

    # setup the reassembler
    nids.param("scan_num_hosts", 0)  # disable portscan detection
    nids.chksum_ctl([('0.0.0.0/0', False)])  # disable checksum verification: jsunpack says it may cause missed traffic
    nids.param("filename", args.PCAP)
    nids.init()
    nids.register_tcp(reassembleTcpStream)
    logging.info("Processing TCP streams...")
    nids.run()

    # process the open streams, which are not processed by pynids
    logging.info("Processing open streams...")
    for c, stream in openstreams.items():
        processTcpStream(stream)

    # run proxy server
    server = ProxyServer((HOST, PORT), ProxyRequestHandler)
    server.allow_reuse_address = True
    try:
        logging.info("Proxy listening on %s:%d" % (HOST, PORT))
        server.serve_forever()
    except KeyboardInterrupt:
        return 0

if __name__ == "__main__":
    sys.exit(main())
