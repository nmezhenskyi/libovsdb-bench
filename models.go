package main

const (
	LogicalSwitchTable     = "Logical_Switch"
	LogicalSwitchPortTable = "Logical_Switch_Port"
	ACLTable               = "ACL"
)

// LogicalSwitch defines an object in Logical_Switch table
type LogicalSwitch struct {
	UUID              string            `ovsdb:"_uuid"`
	ACLs              []string          `ovsdb:"acls"`
	Copp              *string           `ovsdb:"copp"`
	DNSRecords        []string          `ovsdb:"dns_records"`
	ExternalIDs       map[string]string `ovsdb:"external_ids"`
	ForwardingGroups  []string          `ovsdb:"forwarding_groups"`
	LoadBalancer      []string          `ovsdb:"load_balancer"`
	LoadBalancerGroup []string          `ovsdb:"load_balancer_group"`
	Name              string            `ovsdb:"name"`
	OtherConfig       map[string]string `ovsdb:"other_config"`
	Ports             []string          `ovsdb:"ports"`
	QOSRules          []string          `ovsdb:"qos_rules"`
}

// LogicalSwitchPort defines an object in Logical_Switch_Port table
type LogicalSwitchPort struct {
	UUID             string            `ovsdb:"_uuid"`
	Addresses        []string          `ovsdb:"addresses"`
	Dhcpv4Options    *string           `ovsdb:"dhcpv4_options"`
	Dhcpv6Options    *string           `ovsdb:"dhcpv6_options"`
	DynamicAddresses *string           `ovsdb:"dynamic_addresses"`
	Enabled          *bool             `ovsdb:"enabled"`
	ExternalIDs      map[string]string `ovsdb:"external_ids"`
	HaChassisGroup   *string           `ovsdb:"ha_chassis_group"`
	MirrorRules      []string          `ovsdb:"mirror_rules"`
	Name             string            `ovsdb:"name"`
	Options          map[string]string `ovsdb:"options"`
	ParentName       *string           `ovsdb:"parent_name"`
	PortSecurity     []string          `ovsdb:"port_security"`
	Tag              *int              `ovsdb:"tag" validate:"omitempty,min=1,max=4095"`
	TagRequest       *int              `ovsdb:"tag_request" validate:"omitempty,min=0,max=4095"`
	Type             string            `ovsdb:"type"`
	Up               *bool             `ovsdb:"up"`
}

type (
	ACLAction    = string
	ACLDirection = string
	ACLSeverity  = string
)

var (
	ACLActionAllow          ACLAction    = "allow"
	ACLActionAllowRelated   ACLAction    = "allow-related"
	ACLActionAllowStateless ACLAction    = "allow-stateless"
	ACLActionDrop           ACLAction    = "drop"
	ACLActionReject         ACLAction    = "reject"
	ACLDirectionFromLport   ACLDirection = "from-lport"
	ACLDirectionToLport     ACLDirection = "to-lport"
	ACLSeverityAlert        ACLSeverity  = "alert"
	ACLSeverityWarning      ACLSeverity  = "warning"
	ACLSeverityNotice       ACLSeverity  = "notice"
	ACLSeverityInfo         ACLSeverity  = "info"
	ACLSeverityDebug        ACLSeverity  = "debug"
)

// ACL defines an object in ACL table
type ACL struct {
	UUID        string            `ovsdb:"_uuid"`
	Action      ACLAction         `ovsdb:"action" validate:"oneof='allow' 'allow-related' 'allow-stateless' 'drop' 'reject'"`
	Direction   ACLDirection      `ovsdb:"direction" validate:"oneof='from-lport' 'to-lport'"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Label       int               `ovsdb:"label" validate:"min=0,max=4294967295"`
	Log         bool              `ovsdb:"log"`
	Match       string            `ovsdb:"match"`
	Meter       *string           `ovsdb:"meter"`
	Name        *string           `ovsdb:"name" validate:"omitempty,max=63"`
	Options     map[string]string `ovsdb:"options"`
	Priority    int               `ovsdb:"priority" validate:"min=0,max=32767"`
	Severity    *ACLSeverity      `ovsdb:"severity" validate:"omitempty,oneof='alert' 'warning' 'notice' 'info' 'debug'"`
}
