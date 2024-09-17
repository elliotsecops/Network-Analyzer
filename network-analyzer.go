package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketStats struct {
	TCPCount    int
	UDPCount    int
	ICMPCount   int
	OtherCount  int
	TotalBytes  int64
	IPAddresses map[string]int
	Ports       map[int]int
}

func main() {
	var interfaceName string
	var duration int
	var logFile string
	var verbose bool

	flag.StringVar(&interfaceName, "i", "", "Network interface to monitor")
	flag.IntVar(&duration, "t", 60, "Duration of analysis in seconds (0 to run indefinitely)")
	flag.StringVar(&logFile, "o", "", "Output file for logs (optional)")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.Parse()

	if interfaceName == "" {
		log.Fatal("You must specify a network interface with -i")
	}

	if logFile != "" {
		f, err := os.Create(logFile)
		if err != nil {
			log.Fatal("Error creating log file:", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening interface:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var wg sync.WaitGroup
	stats := PacketStats{IPAddresses: make(map[string]int), Ports: make(map[int]int)}
	var statsMutex sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		for packet := range packetSource.Packets() {
			statsMutex.Lock()
			processPacket(packet, &stats, verbose)
			statsMutex.Unlock()
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			printStats(&stats)
		}
	}()

	if duration > 0 {
		time.Sleep(time.Duration(duration) * time.Second)
		handle.Close()
	}

	wg.Wait()
	printFinalStats(&stats)
}

func processPacket(packet gopacket.Packet, stats *PacketStats, verbose bool) {
	stats.TotalBytes += int64(len(packet.Data()))

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		stats.TCPCount++
		tcp, _ := tcpLayer.(*layers.TCP)
		stats.Ports[int(tcp.SrcPort)]++
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		stats.UDPCount++
		udp, _ := udpLayer.(*layers.UDP)
		stats.Ports[int(udp.SrcPort)]++
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		stats.ICMPCount++
	} else {
		stats.OtherCount++
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		stats.IPAddresses[ip.SrcIP.String()]++
	}

	if verbose {
		log.Printf("Packet: %s\n", packet.Dump())
	}
}

func printStats(stats *PacketStats) {
	fmt.Printf("\nCurrent Statistics:\n")
	fmt.Printf("TCP Packets: %d\n", stats.TCPCount)
	fmt.Printf("UDP Packets: %d\n", stats.UDPCount)
	fmt.Printf("ICMP Packets: %d\n", stats.ICMPCount)
	fmt.Printf("Other Packets: %d\n", stats.OtherCount)
	fmt.Printf("Total Bytes: %d\n", stats.TotalBytes)
}

func printFinalStats(stats *PacketStats) {
	printStats(stats)
	fmt.Println("\nTop 5 Active IPs:")
	ips := make([]string, 0, len(stats.IPAddresses))
	for ip := range stats.IPAddresses {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return stats.IPAddresses[ips[i]] > stats.IPAddresses[ips[j]]
	})
	for i, ip := range ips[:min(5, len(ips))] {
		fmt.Printf("%d. %s: %d packets\n", i+1, ip, stats.IPAddresses[ip])
	}

	fmt.Println("\nTop 5 Active Ports:")
	ports := make([]int, 0, len(stats.Ports))
	for port := range stats.Ports {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		return stats.Ports[ports[i]] > stats.Ports[ports[j]]
	})
	for i, port := range ports[:min(5, len(ports))] {
		fmt.Printf("%d. Port %d: %d packets\n", i+1, port, stats.Ports[port])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
