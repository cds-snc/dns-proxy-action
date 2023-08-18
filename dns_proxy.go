package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

func checkWildcard(wildcard string, domain string) bool {
	wildcardParts := strings.Split(wildcard, ".")
	domainParts := strings.Split(domain, ".")

	if len(wildcardParts) != len(domainParts) {
		return false
	}

	for i, part := range wildcardParts {
		if part != "*" && part != domainParts[i] {
			return false
		}
	}

	return true
}

func dnsProxyServer(config *Config) {
	// Set up a UDP listener
	listenAddr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	um, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Fatalln("Error creating UDP listener:", err)
		return
	}
	defer um.Close()

	log.Infoln("DNS proxy server listening on", listenAddr)

	// Loop to handle incoming DNS requests
	for {
		buf := make([]byte, 65535)
		n, clientAddr, err := um.ReadFrom(buf)
		if err != nil {
			log.Warningln("Error reading from UDP connection:", err)
			continue
		}

		// Parse the DNS request
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeDNS, gopacket.Default)
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dnsRequest := dnsLayer.(*layers.DNS)
			go proxyRequest(um.(*net.UDPConn), clientAddr, dnsRequest, config)
		}
	}
}

func filterDns(request *layers.DNS, config *Config) bool {
	// Check if the DNS request is a query
	if request.QR {
		return false
	}

	// Check if the DNS request is a query for an A record
	if len(request.Questions) != 1 || request.Questions[0].Type != layers.DNSTypeA {
		return false
	}

	// Check if the DNS request is for a domain we want to block
	domain := string(request.Questions[0].Name)
	log.Debugln("DNS request for", domain)

	// Check if we are using a safelist or a blocklist
	if len(config.SafeList) > 0 {
		for _, safeDomain := range config.SafeList {
			if checkWildcard(safeDomain, domain) {
				log.Debugln("DNS request for", domain, "allowed")
				return false
			}
		}
		log.Warnln("DNS request for", domain, "blocked")
		return true
	} else {
		for _, blockedDomain := range config.BlockList {
			if checkWildcard(blockedDomain, domain) {
				log.Warnln("DNS request for", domain, "blocked")
				return true
			}
		}
	}
	return false
}

func proxyRequest(um *net.UDPConn, clientAddr net.Addr, request *layers.DNS, config *Config) {
	if filterDns(request, config) {
		// Create a DNS response
		response := &layers.DNS{
			ID:           request.ID,
			QR:           true,
			OpCode:       request.OpCode,
			AA:           false,
			TC:           false,
			RD:           request.RD,
			RA:           false,
			Z:            request.Z,
			ResponseCode: layers.DNSResponseCodeNoErr,
			QDCount:      1,
			ANCount:      0,
			NSCount:      0,
			ARCount:      0,
			Questions:    request.Questions,
		}

		// Serialize the DNS response and send it to the client
		responseBuf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(responseBuf, gopacket.SerializeOptions{},
			response,
		)
		_, err := um.WriteTo(responseBuf.Bytes(), clientAddr)
		if err != nil {
			log.Warningln("Error sending DNS response to client:", err)
		}
	} else {
		// Create a connection to the upstream DNS server
		upstreamAddr := fmt.Sprintf("%s:53", config.UpstreamServer)
		upstreamConn, err := net.Dial("udp", upstreamAddr)
		if err != nil {
			log.Warningln("Error connecting to upstream DNS server:", err)
			return
		}
		defer upstreamConn.Close()

		// Serialize the DNS request and send it to the upstream DNS server
		requestBuf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(requestBuf, gopacket.SerializeOptions{},
			request,
		)
		_, err = upstreamConn.Write(requestBuf.Bytes())
		if err != nil {
			log.Warningln("Error sending DNS request to upstream:", err)
			return
		}

		// Set a timeout for reading the response from the upstream DNS server
		upstreamConn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// Read the response from the upstream DNS server
		responseBuf := make([]byte, 65535)
		n, err := upstreamConn.Read(responseBuf)
		if err != nil {
			log.Warningln("Error reading DNS response from upstream:", err)
			return
		}

		// Parse the DNS response
		responsePacket := gopacket.NewPacket(responseBuf[:n], layers.LayerTypeDNS, gopacket.Default)
		if dnsLayer := responsePacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dnsResponse := dnsLayer.(*layers.DNS)
			// Send the DNS response back to the client
			_, err := um.WriteTo(dnsResponse.BaseLayer.Contents, clientAddr)
			if err != nil {
				log.Warningln("Error sending DNS response to client:", err)
			}
		}

	}
}
