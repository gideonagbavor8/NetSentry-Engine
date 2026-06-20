# Overview

As a software engineer expanding my knowledge of low-level systems and protocol behavior, I wanted to understand how telemetry transport streams operate outside high-level framework wrappers. This project focuses on capturing live data packets, classifying network protocols on the fly, and shipping structured tracking summaries to a centralized monitoring console using raw TCP streaming sockets.

This software consists of two components: a network packet sniffing agent that runs locally to intercept active traffic layers, and a centralized monitoring dashboard server that listens continuously for agent telemetry connections. When traffic crosses the network card, the agent extracts structural attributes (including protocol identification, endpoint connections, and raw payload data), checks compliance rules for unencrypted data patterns, and sends a custom-formatted string directly to the listener.

I created this software to gain practical experience with socket programming lifecycles and data stream formatting. Building this tool helped me internalize how transport layers manage connection endpoints, how byte arrays map into strings across socket links, and how custom text parsing layouts work under live operational conditions.

[Software Demo Video] https://www.loom.com/share/431bc95d44f6426f95b094f21b4d3719

# Development Environment

To construct this network monitoring application, I utilized Visual Studio Code as the primary Integrated Development Environment (IDE) along with a native command-line terminal to run separate concurrent instances. Network traffic capturing was enabled by installing packet capture drivers locally to interface directly with the network adapter hardware layer.

The entire application was authored in the Python programming language. I utilized standard socket libraries to manage networking lifecycles, sys packages for connection handling controls, and the Scapy library to sniff and decode raw packets directly from the loopback interface.

# Useful Websites

* [Python Socket Programming Documentation](https://docs.python.org/3/library/socket.html)
* [Scapy Packet Sniffing Official Guide](https://scapy.readthedocs.io/en/latest/usage.html)
* [W3Schools Python String Split Reference](https://www.w3schools.com/python/ref_string_split.asp)