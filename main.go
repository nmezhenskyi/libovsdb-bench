package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
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
	schema, err := model.NewClientDBModel("OVN_Northbound", map[string]model.Model{
		"Logical_Switch":      &LogicalSwitch{},
		"Logical_Switch_Port": &LogicalSwitchPort{},
		"ACL":                 &ACL{},
	})
	if err != nil {
		return fmt.Errorf("Failed to initialize client schema: %w", err)
	}

	c, err := client.NewOVSDBClient(schema, client.WithEndpoint(SocketPath))
	if err != nil {
		return fmt.Errorf("Failed to create client: %w", err)
	}

	err = c.Connect(context.Background())
	if err != nil {
		return fmt.Errorf("Failed to connect to OVN Northbound database: %w", err)
	}
	defer c.Close()

	err = c.Echo(context.Background())
	if err != nil {
		return fmt.Errorf("Failed to send echo to OVN Northbound database: %w", err)
	}

	monitorCookie, err := c.Monitor(context.Background(), c.NewMonitor(
		client.WithTable(&LogicalSwitch{}),
		client.WithTable(&LogicalSwitchPort{}),
		client.WithTable(&ACL{}),
	))
	if err != nil {
		return fmt.Errorf("Failed to set up libovsdb monitor: %w", err)
	}

	defer c.MonitorCancel(context.Background(), monitorCookie)

	for i := range n {
		// Prepare the context with timeout for the transaction.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		lsName := fmt.Sprintf("%s_lib_%d", Prefix, i)
		lspName := fmt.Sprintf("%s_port", lsName)

		// Check if the switch exists to add the cost of lookup.
		existingLS := &LogicalSwitch{Name: lsName}
		err := c.Get(ctx, existingLS)
		if err == nil {
			// Here we just continue, but the cost of the check is included in the benchmark.
			continue
		} else if !errors.Is(err, client.ErrNotFound) {
			return fmt.Errorf("Cache lookup failed: %w", err)
		}

		// Define the logical switch port.
		lsp := &LogicalSwitchPort{
			Name: lspName,
		}

		// Define the ACL.
		acl := &ACL{
			Action:      "allow-related",
			Direction:   "to-lport",
			Match:       "ip4.src==10.0.0.1",
			Priority:    1001,
			ExternalIDs: map[string]string{"created_by": "bench_test"},
		}

		var operations []ovsdb.Operation

		// Create switch port.
		opLSP, err := c.Create(lsp)
		if err != nil {
			return fmt.Errorf("Failed to prepare create operation for switch port: %w", err)
		}

		opLSP[0].UUIDName = "row_lsp"
		operations = append(operations, opLSP...)

		// Create ACL.
		opACL, err := c.Create(acl)
		if err != nil {
			return fmt.Errorf("Failed to prepare create operation for ACL: %w", err)
		}

		opACL[0].UUIDName = "row_acl"
		operations = append(operations, opACL...)

		// Create switch and link switch port to ACL.
		// Use a helper model to indicate we want to insert the UUIDs of the new rows.
		lsModel := &LogicalSwitch{
			Name:  lsName,
			Ports: []string{"row_lsp"},
			ACLs:  []string{"row_acl"},
		}

		opLS, err := c.Create(lsModel)
		if err != nil {
			return fmt.Errorf("Failed to prepare create operation for switch: %w", err)
		}

		operations = append(operations, opLS...)

		resp, err := c.Transact(ctx, operations...)
		if err != nil {
			return fmt.Errorf("Failed to commit transaction: %w", err)
		}

		_, err = ovsdb.CheckOperationResults(resp, operations)
		if err != nil {
			return fmt.Errorf("Operation failed: %w", err)
		}
	}

	return nil
}

func runCLI(n int) error {
	for i := range n {
		lsName := fmt.Sprintf("%s_cli_%d", Prefix, i)
		lspName := fmt.Sprintf("%s_port", lsName)

		cmd := exec.Command("ovn-nbctl",
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
