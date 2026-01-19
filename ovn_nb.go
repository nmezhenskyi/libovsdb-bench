package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-logr/logr"
	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
)

// NB represents a Northbound database client.
type NB struct {
	client client.Client
	cookie client.MonitorCookie

	sbCond    *sync.Cond
	sbCurrent int
}

type nbGlobalHandler struct {
	nb *NB
}

func (h *nbGlobalHandler) OnAdd(table string, newModel model.Model) {
	h.OnUpdate(table, nil, newModel)
}

func (h *nbGlobalHandler) OnUpdate(table string, oldModel, newModel model.Model) {
	if table != "NB_Global" {
		return
	}

	nbGlobal, ok := newModel.(*NBGlobal)
	if !ok {
		return
	}

	h.nb.sbCond.L.Lock()
	h.nb.sbCurrent = nbGlobal.SbCfg
	h.nb.sbCond.Broadcast()
	h.nb.sbCond.L.Unlock()
}

func (h *nbGlobalHandler) OnDelete(table string, m model.Model) {}

// NewNB initialises new OVN client for Northbound operations.
func NewNB(dbAddr string) (*NB, error) {
	// Create the client struct.
	c := &NB{
		sbCond: sync.NewCond(&sync.Mutex{}),
	}

	// Prepare the OVSDB client.
	dbSchema, err := FullDatabaseModel()
	if err != nil {
		return nil, err
	}

	// Add some missing indexes.
	dbSchema.SetIndexes(map[string][]model.ClientIndex{
		"Load_Balancer":       {{Columns: []model.ColumnKey{{Column: "name"}}}},
		"Logical_Router":      {{Columns: []model.ColumnKey{{Column: "name"}}}},
		"Logical_Switch":      {{Columns: []model.ColumnKey{{Column: "name"}}}},
		"Logical_Switch_Port": {{Columns: []model.ColumnKey{{Column: "name"}}}},
	})

	discard := logr.Discard()

	options := []client.Option{client.WithLogger(&discard), client.WithReconnect(5*time.Second, &backoff.ZeroBackOff{})}
	for entry := range strings.SplitSeq(dbAddr, ",") {
		options = append(options, client.WithEndpoint(entry))
	}

	// Connect to OVSDB.
	ovn, err := client.NewOVSDBClient(dbSchema, options...)
	if err != nil {
		return nil, fmt.Errorf("Failed to create client: %w", err)
	}

	err = ovn.Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to OVN Northbound database: %w", err)
	}

	err = ovn.Echo(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Failed to send echo to OVN Northbound database: %w", err)
	}

	ovn.Cache().AddEventHandler(&nbGlobalHandler{nb: c})

	monitorCookie, err := ovn.MonitorAll(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Failed to set up libovsdb monitor: %w", err)
	}

	// Set the fields needed for the libovsdb client.
	c.client = ovn
	c.cookie = monitorCookie

	// Populate initial state.
	// We must populate sbCurrent immediately after monitoring,
	// otherwise the first waitForSB call might block if no update happens soon.
	var list []NBGlobal
	if err := ovn.List(context.Background(), &list); err == nil && len(list) > 0 {
		c.sbCond.L.Lock()
		c.sbCurrent = list[0].SbCfg
		c.sbCond.L.Unlock()
	}

	// Set finalizer to stop the monitor.
	runtime.SetFinalizer(c, func(o *NB) {
		_ = ovn.MonitorCancel(context.Background(), o.cookie)
		ovn.Close()
	})

	return c, nil
}

func (c *NB) CreateLogicalSwitch(lsName string, lspName string) error {
	// Prepare the context with timeout for the transaction.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if the switch exists to add the cost of lookup.
	existingLS := &LogicalSwitch{Name: lsName}
	err := c.get(ctx, existingLS)
	if err != nil && !errors.Is(err, client.ErrNotFound) {
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
	opLSP, err := c.client.Create(lsp)
	if err != nil {
		return fmt.Errorf("Failed to prepare create operation for switch port: %w", err)
	}

	opLSP[0].UUIDName = "row_lsp"
	operations = append(operations, opLSP...)

	// Create ACL.
	opACL, err := c.client.Create(acl)
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

	opLS, err := c.client.Create(lsModel)
	if err != nil {
		return fmt.Errorf("Failed to prepare create operation for switch: %w", err)
	}

	operations = append(operations, opLS...)

	// Apply the changes and wait for the changes to be take effect in the SB database.
	err = c.transactAndWaitSB(ctx, operations...)
	if err != nil {
		return fmt.Errorf("Failed to commit transaction: %w", err)
	}

	return nil
}

// get is used to perform a libovsdb Get call while also making use of the custom defined indexes.
// The libovsdb Get() function only uses the built-in indices rather than considering the user provided ones.
// This seems to be by design but makes it harder to fetch records from some tables.
func (o *NB) get(ctx context.Context, m model.Model) error {
	var collection any

	// Check if the model is one of the types with custom defined index.
	switch m.(type) {
	case *LoadBalancer:
		s := []LoadBalancer{}
		collection = &s
	case *LogicalRouter:
		s := []LogicalRouter{}
		collection = &s
	case *LogicalSwitch:
		s := []LogicalSwitch{}
		collection = &s
	case *LogicalSwitchPort:
		s := []LogicalSwitchPort{}
		collection = &s
	default:
		// Fallback to normal Get.
		return o.client.Get(ctx, m)
	}

	// Check and assign the resulting value.
	err := o.client.Where(m).List(ctx, collection)
	if err != nil {
		return err
	}

	rVal := reflect.ValueOf(collection)
	if rVal.Kind() != reflect.Pointer {
		return errors.New("Bad collection type")
	}

	rVal = rVal.Elem()
	if rVal.Kind() != reflect.Slice {
		return errors.New("Bad collection type")
	}

	if rVal.Len() == 0 {
		return client.ErrNotFound
	}

	if rVal.Len() > 1 {
		return errors.New("too many objects found")
	}

	reflect.ValueOf(m).Elem().Set(rVal.Index(0))
	return nil
}

// transactAndWaitSB wraps a normal libovsdb transaction with the `nb_cfg` increment and logic to wait for
// configuration changes to be applied in the Southbound database.
func (o *NB) transactAndWaitSB(ctx context.Context, operations ...ovsdb.Operation) error {
	// Get the current NB_Global row.
	nbGlobalList := []NBGlobal{}
	err := o.client.List(ctx, &nbGlobalList)
	if err != nil {
		return fmt.Errorf("Failed listing NB_Global: %w", err)
	}

	if len(nbGlobalList) == 0 {
		return errors.New("NB_Global table is empty")
	}

	// There is only ever one row in the NB_Global table.
	nbGlobal := nbGlobalList[0]

	// Increment `nb_cfg` to signify the ovn-northd that we want to wait until the configuration changes take place.
	targetCfg := nbGlobal.NbCfg + 1

	incrementOp, err := o.client.Where(&nbGlobal).Update(&NBGlobal{
		NbCfg: targetCfg,
	})
	if err != nil {
		return fmt.Errorf("Failed preparing update operation: %w", err)
	}

	operations = append(operations, incrementOp...)

	// Apply the database changes.
	resp, err := o.client.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("Failed applying transaction: %w", err)
	}

	_, err = ovsdb.CheckOperationResults(resp, operations)
	if err != nil {
		return fmt.Errorf("OVN operation failed: %w", err)
	}

	return o.waitForSB(ctx, targetCfg)
}

// waitForSB implements a polling logic to wait until the configuration changes have
// been applied in the Southbound database according to `targetCfg` value or the context expired.
func (o *NB) waitForSB(ctx context.Context, targetCfg int) error {
	o.sbCond.L.Lock()

	// Fast path: already synced.
	if o.sbCurrent >= targetCfg {
		o.sbCond.L.Unlock() // Unlock before returning.
		return nil
	}

	// Wait path:
	done := make(chan struct{})

	go func() {
		o.sbCond.L.Lock()
		defer o.sbCond.L.Unlock()

		// Loop until condition met OR context dead
		for o.sbCurrent < targetCfg {
			// Check context before waiting.
			// If the parent cancelled, we must exit to avoid leaking.
			if ctx.Err() != nil {
				return
			}

			o.sbCond.Wait()

			// Check context immediately after waking.
			// We might have been woken up specifically because of a timeout.
			if ctx.Err() != nil {
				return
			}
		}

		close(done)
	}()

	o.sbCond.L.Unlock()

	select {
	case <-done:
		return nil

	case <-ctx.Done():
		// We hit the timeout. The goroutine above is likely asleep in Wait().
		// We MUST wake it up so it can hit the 'if ctx.Err()' check and exit.

		// Note: Broadcast() is allowed without a lock, but grabbing it ensures
		// we don't race with the child entering the Wait() state.
		o.sbCond.L.Lock()
		o.sbCond.Broadcast()
		o.sbCond.L.Unlock()

		return errors.New("Timeout waiting for OVN to sync")
	}
}
