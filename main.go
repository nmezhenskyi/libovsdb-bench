package main

import (
	"flag"
	"fmt"
	"log"
	"os/exec"
	"time"
)

const (
	SocketPath = "unix:/run/ovn/ovnnb_db.sock"
	Prefix     = "bench_test"
)

func main() {
	mode := flag.String("mode", "lib", "Mode: 'lib' (libovsdb) or 'cli' (ovn-nbctl)")
	count := flag.Int("count", 50, "Number of logical switches to create")
	flag.Parse()

	log.Printf("------------------------------------------------\n")
	log.Printf("Starting Benchmark | Mode: %s | Iterations: %d\n", *mode, *count)
	start := time.Now()

	var err error

	switch *mode {
	case "lib":
		err = runLib(*count)
	case "cli":
		err = runCLI(*count)
	default:
		log.Fatalln("Invalid mode")
	}

	if err != nil {
		log.Fatalf("Benchmark failed: %v\n", err)
	}

	totalDuration := time.Since(start)
	avg := totalDuration / time.Duration(*count)
	opsPerSec := float64(*count) / totalDuration.Seconds()

	log.Printf("------------------------------------------------\n")
	log.Printf("Results for %d iterations:", *count)
	log.Printf("Total Time: %v", totalDuration)
	log.Printf("Avg Latency: %v/op", avg)
	log.Printf("Throughput:  %.2f ops/sec", opsPerSec)
	log.Printf("------------------------------------------------\n")
}

func runLib(n int) error {
	c, err := NewNB(SocketPath)
	if err != nil {
		return err
	}

	for i := range n {
		lsName := fmt.Sprintf("%s_lib_%d", Prefix, i)
		lspName := fmt.Sprintf("%s_port", lsName)

		err := c.CreateLogicalSwitch(lsName, lspName)
		if err != nil {
			return fmt.Errorf("CreateLogicalSwitch: %w", err)
		}
	}

	return nil
}

func runCLI(n int) error {
	for i := range n {
		lsName := fmt.Sprintf("%s_cli_%d", Prefix, i)
		lspName := fmt.Sprintf("%s_port", lsName)

		cmd := exec.Command("ovn-nbctl",
			"--wait=sb", "--timeout=10",
			// Command 1: Create switch
			"--may-exist", "ls-add", lsName,
			"--",
			// Command 2: Create switch port
			"--may-exist", "lsp-add", lsName, lspName,
			"--",
			// Command 3: Add ACL
			"--may-exist", "acl-add", lsName, "to-lport", "1001", "ip4.src==10.0.0.1", "allow-related",
		)

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ovn-nbctl failed at iteration %d: %w", i, err)
		}
	}

	return nil
}
