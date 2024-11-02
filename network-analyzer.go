package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLength = 1600 // Named constant
	updateInterval = 5 * time.Second
)

var (
	statsMutex sync.Mutex
)

type PacketStats struct {
	TotalPackets int64
	TotalBytes   int64
	TCPCount     int64
	UDPCount     int64
	ICMPCount    int64
	IPAddresses  map[string]int
	Ports        map[int]int
}

func main() {
	interfaceName := flag.String("i", "eth0", "Network interface to capture from")
	duration := flag.Duration("t", 0, "Duration to capture packets (0 for indefinite)")
	verbose := flag.Bool("v", false, "Enable verbose logging")
	logFile := flag.String("o", "", "Output log file (CSV format)")
	flag.Parse()

	var csvWriter *csv.Writer
	if *logFile != "" {
		csvFile, err := os.Create(*logFile)
		if err != nil {
			log.Fatalf("Error creating CSV file: %v", err)
		}
		defer csvFile.Close()

		csvWriter = csv.NewWriter(csvFile)
		defer csvWriter.Flush()
		csvWriter.Write([]string{"Timestamp", "Source IP", "Destination IP", "Protocol", "Length"})
	}

	handle, err := pcap.OpenLive(*interfaceName, snapshotLength, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", *interfaceName, err)
	}
	defer handle.Close() // Ensure handle is closed even if the program exits unexpectedly

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stats := &PacketStats{
		IPAddresses: make(map[string]int),
		Ports:       make(map[int]int),
	}

	var wg sync.WaitGroup
	wg.Add(2) // Two goroutines now (packet processing and stats printing)

	// Signal handling (unchanged)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	startTime := time.Now()

	var csvWriteErrors int64 // Counter for CSV write errors

	// Packet Processing Goroutine (Corrected)
	go func() {
		defer wg.Done()
		var timer *time.Timer // Declare timer outside the if block
		if *duration > 0 {
			timer = time.NewTimer(*duration) // Create the timer if a duration is set.
			defer timer.Stop() // Ensure we always stop the timer whether we hit the duration or not.
		}

		packets := packetSource.Packets() // Get the channel, but don't use range

		for packet, ok := <-packets; ok; packet, ok = <-packets {
			processPacket(packet, stats, *verbose, csvWriter, &csvWriteErrors) // Pass error counter
		}

		if timer != nil {
			<-timer.C // Wait for the timer to expire if it was set
			handle.Close()
			fmt.Println("Capture duration reached.") // or log this for debugging.
		}
	}()

	go printStatsWg(stats, &wg, c, handle)

	wg.Wait()
	printFinalStats(stats)

	fmt.Printf("\nCSV Write Errors: %d\n", csvWriteErrors) // Report at the end
}

func processPacket(packet gopacket.Packet, stats *PacketStats, verbose bool, csvWriter *csv.Writer, csvWriteErrors *int64) {
	atomic.AddInt64(&stats.TotalPackets, 1)
	atomic.AddInt64(&stats.TotalBytes, int64(len(packet.Data())))

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok {
			statsMutex.Lock()
			stats.IPAddresses[ip.SrcIP.String()]++
			statsMutex.Unlock()
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			atomic.AddInt64(&stats.TCPCount, 1)
			statsMutex.Lock()
			stats.Ports[int(tcp.SrcPort)]++
			statsMutex.Unlock()
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			atomic.AddInt64(&stats.UDPCount, 1)
			statsMutex.Lock()
			stats.Ports[int(udp.SrcPort)]++
			statsMutex.Unlock()
		}
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if _, ok := icmpLayer.(*layers.ICMPv4); ok {
			atomic.AddInt64(&stats.ICMPCount, 1)
		}
	}

	if csvWriter != nil {
		timestamp := time.Now().Format(time.RFC3339)
		var srcIP, dstIP, protocol string

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			if ip, ok := ipLayer.(*layers.IPv4); ok {
				srcIP = ip.SrcIP.String()
				dstIP = ip.DstIP.String()
			}
		}

		protocol = packet.NetworkLayer().LayerType().String()
		length := len(packet.Data())
		if err := csvWriter.Write([]string{timestamp, srcIP, dstIP, protocol, fmt.Sprint(length)}); err != nil {
			log.Printf("Error writing to CSV: %v", err) // Log error
			atomic.AddInt64(csvWriteErrors, 1) // Increment error counter atomically
		}
	}

	if verbose {
		log.Printf("Packet: %+v", packet) // Use %+v for more detailed output
	}
}

func printStats(stats *PacketStats) {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	fmt.Printf("\n--- Traffic Statistics ---\n")
	fmt.Printf("Total Packets: %d\n", stats.TotalPackets)
	fmt.Printf("Total Bytes: %d\n", stats.TotalBytes)
	fmt.Printf("TCP Packets: %d\n", stats.TCPCount)
	fmt.Printf("UDP Packets: %d\n", stats.UDPCount)
	fmt.Printf("ICMP Packets: %d\n", stats.ICMPCount)
}

func printStatsWg(stats *PacketStats, wg *sync.WaitGroup, c <-chan os.Signal, handle *pcap.Handle) {
	defer wg.Done() // Waitgroup decreased once the goroutine ends
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			printStats(stats)
		case <-c: // Handle interrupt signal (Ctrl+C)
			fmt.Println("\nInterrupt received. Exiting...")
			handle.Close() // Stop capturing packets
			return         // Exit the goroutine
		}
	}
}

func printFinalStats(stats *PacketStats) {
	printStats(stats)

	fmt.Println("\nTop 5 Active IPs:")
	topIPs := getTopN(stats.IPAddresses, 5)
	for _, ip := range topIPs {
		fmt.Printf("%s: %d\n", ip.Key, ip.Value)
	}

	fmt.Println("\nTop 5 Active Ports:")
	topPorts := getTopN(stats.Ports, 5)
	for _, port := range topPorts {
		fmt.Printf("%d: %d\n", port.Key, port.Value)
	}
}

type KV[K comparable] struct {
	Key   K
	Value int
}

func getTopN[K comparable](m map[K]int, n int) []KV[K] {
	var sorted []KV[K]
	for k, v := range m {
		sorted = append(sorted, KV[K]{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	return sorted[:minInt(n, len(sorted))] // Using minInt
}

func minInt(a, b int) int { // Helper function
	if a < b {
		return a
	}
	return b
}
