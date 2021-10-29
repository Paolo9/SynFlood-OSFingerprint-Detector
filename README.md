# SynFlood-OSFingerprint-Detector
A simple Python3 program for SYN Flood attacks and OS Fingerprint attempts detection using Scapy

The program analyzes, through the scapy sniff function, the traffic on the network interface initially chosen by the user. 
Each packet is checked to verify that it is legitimate and not an attempt of OS Fingerprint or a beginning of SYN Flood attack. 
Each analysis result is recorded on a log file.
