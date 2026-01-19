package main

const (
	ACLTable                      = "ACL"
	AddressSetTable               = "Address_Set"
	BFDTable                      = "BFD"
	ChassisTemplateVarTable       = "Chassis_Template_Var"
	ConnectionTable               = "Connection"
	CoppTable                     = "Copp"
	DHCPOptionsTable              = "DHCP_Options"
	DNSTable                      = "DNS"
	ForwardingGroupTable          = "Forwarding_Group"
	GatewayChassisTable           = "Gateway_Chassis"
	HAChassisTable                = "HA_Chassis"
	HAChassisGroupTable           = "HA_Chassis_Group"
	LoadBalancerTable             = "Load_Balancer"
	LoadBalancerGroupTable        = "Load_Balancer_Group"
	LoadBalancerHealthCheckTable  = "Load_Balancer_Health_Check"
	LogicalRouterTable            = "Logical_Router"
	LogicalRouterPolicyTable      = "Logical_Router_Policy"
	LogicalRouterPortTable        = "Logical_Router_Port"
	LogicalRouterStaticRouteTable = "Logical_Router_Static_Route"
	LogicalSwitchTable            = "Logical_Switch"
	LogicalSwitchPortTable        = "Logical_Switch_Port"
	MeterTable                    = "Meter"
	MeterBandTable                = "Meter_Band"
	MirrorTable                   = "Mirror"
	NATTable                      = "NAT"
	NBGlobalTable                 = "NB_Global"
	PortGroupTable                = "Port_Group"
	QoSTable                      = "QoS"
	SSLTable                      = "SSL"
	StaticMACBindingTable         = "Static_MAC_Binding"
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

// AddressSet defines an object in Address_Set table
type AddressSet struct {
	UUID        string            `ovsdb:"_uuid"`
	Addresses   []string          `ovsdb:"addresses"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Name        string            `ovsdb:"name"`
}

type (
	BFDStatus = string
)

var (
	BFDStatusDown      BFDStatus = "down"
	BFDStatusInit      BFDStatus = "init"
	BFDStatusUp        BFDStatus = "up"
	BFDStatusAdminDown BFDStatus = "admin_down"
)

// BFD defines an object in BFD table
type BFD struct {
	UUID        string            `ovsdb:"_uuid"`
	DetectMult  *int              `ovsdb:"detect_mult" validate:"omitempty,min=1"`
	DstIP       string            `ovsdb:"dst_ip"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	LogicalPort string            `ovsdb:"logical_port"`
	MinRx       *int              `ovsdb:"min_rx"`
	MinTx       *int              `ovsdb:"min_tx" validate:"omitempty,min=1"`
	Options     map[string]string `ovsdb:"options"`
	Status      *BFDStatus        `ovsdb:"status" validate:"omitempty,oneof='down' 'init' 'up' 'admin_down'"`
}

// ChassisTemplateVar defines an object in Chassis_Template_Var table
type ChassisTemplateVar struct {
	UUID        string            `ovsdb:"_uuid"`
	Chassis     string            `ovsdb:"chassis"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Variables   map[string]string `ovsdb:"variables"`
}

// Connection defines an object in Connection table
type Connection struct {
	UUID            string            `ovsdb:"_uuid"`
	ExternalIDs     map[string]string `ovsdb:"external_ids"`
	InactivityProbe *int              `ovsdb:"inactivity_probe"`
	IsConnected     bool              `ovsdb:"is_connected"`
	MaxBackoff      *int              `ovsdb:"max_backoff" validate:"omitempty,min=1000"`
	OtherConfig     map[string]string `ovsdb:"other_config"`
	Status          map[string]string `ovsdb:"status"`
	Target          string            `ovsdb:"target"`
}

// Copp defines an object in Copp table
type Copp struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Meters      map[string]string `ovsdb:"meters"`
	Name        string            `ovsdb:"name"`
}

// DHCPOptions defines an object in DHCP_Options table
type DHCPOptions struct {
	UUID        string            `ovsdb:"_uuid"`
	Cidr        string            `ovsdb:"cidr"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Options     map[string]string `ovsdb:"options"`
}

// DNS defines an object in DNS table
type DNS struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Records     map[string]string `ovsdb:"records"`
}

// ForwardingGroup defines an object in Forwarding_Group table
type ForwardingGroup struct {
	UUID        string            `ovsdb:"_uuid"`
	ChildPort   []string          `ovsdb:"child_port" validate:"min=1"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Liveness    bool              `ovsdb:"liveness"`
	Name        string            `ovsdb:"name"`
	Vip         string            `ovsdb:"vip"`
	Vmac        string            `ovsdb:"vmac"`
}

// GatewayChassis defines an object in Gateway_Chassis table
type GatewayChassis struct {
	UUID        string            `ovsdb:"_uuid"`
	ChassisName string            `ovsdb:"chassis_name"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Name        string            `ovsdb:"name"`
	Options     map[string]string `ovsdb:"options"`
	Priority    int               `ovsdb:"priority" validate:"min=0,max=32767"`
}

// HAChassis defines an object in HA_Chassis table
type HAChassis struct {
	UUID        string            `ovsdb:"_uuid"`
	ChassisName string            `ovsdb:"chassis_name"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Priority    int               `ovsdb:"priority" validate:"min=0,max=32767"`
}

// HAChassisGroup defines an object in HA_Chassis_Group table
type HAChassisGroup struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	HaChassis   []string          `ovsdb:"ha_chassis"`
	Name        string            `ovsdb:"name"`
}

type (
	LoadBalancerProtocol        = string
	LoadBalancerSelectionFields = string
)

var (
	LoadBalancerProtocolTCP           LoadBalancerProtocol        = "tcp"
	LoadBalancerProtocolUDP           LoadBalancerProtocol        = "udp"
	LoadBalancerProtocolSCTP          LoadBalancerProtocol        = "sctp"
	LoadBalancerSelectionFieldsEthSrc LoadBalancerSelectionFields = "eth_src"
	LoadBalancerSelectionFieldsEthDst LoadBalancerSelectionFields = "eth_dst"
	LoadBalancerSelectionFieldsIPSrc  LoadBalancerSelectionFields = "ip_src"
	LoadBalancerSelectionFieldsIPDst  LoadBalancerSelectionFields = "ip_dst"
	LoadBalancerSelectionFieldsTpSrc  LoadBalancerSelectionFields = "tp_src"
	LoadBalancerSelectionFieldsTpDst  LoadBalancerSelectionFields = "tp_dst"
)

// LoadBalancer defines an object in Load_Balancer table
type LoadBalancer struct {
	UUID            string                        `ovsdb:"_uuid"`
	ExternalIDs     map[string]string             `ovsdb:"external_ids"`
	HealthCheck     []string                      `ovsdb:"health_check"`
	IPPortMappings  map[string]string             `ovsdb:"ip_port_mappings"`
	Name            string                        `ovsdb:"name"`
	Options         map[string]string             `ovsdb:"options"`
	Protocol        *LoadBalancerProtocol         `ovsdb:"protocol" validate:"omitempty,oneof='tcp' 'udp' 'sctp'"`
	SelectionFields []LoadBalancerSelectionFields `ovsdb:"selection_fields" validate:"dive,oneof='eth_src' 'eth_dst' 'ip_src' 'ip_dst' 'tp_src' 'tp_dst'"`
	Vips            map[string]string             `ovsdb:"vips"`
}

// LoadBalancerGroup defines an object in Load_Balancer_Group table
type LoadBalancerGroup struct {
	UUID         string   `ovsdb:"_uuid"`
	LoadBalancer []string `ovsdb:"load_balancer"`
	Name         string   `ovsdb:"name"`
}

// LoadBalancerHealthCheck defines an object in Load_Balancer_Health_Check table
type LoadBalancerHealthCheck struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Options     map[string]string `ovsdb:"options"`
	Vip         string            `ovsdb:"vip"`
}

// LogicalRouter defines an object in Logical_Router table
type LogicalRouter struct {
	UUID              string            `ovsdb:"_uuid"`
	Copp              *string           `ovsdb:"copp"`
	Enabled           *bool             `ovsdb:"enabled"`
	ExternalIDs       map[string]string `ovsdb:"external_ids"`
	LoadBalancer      []string          `ovsdb:"load_balancer"`
	LoadBalancerGroup []string          `ovsdb:"load_balancer_group"`
	Name              string            `ovsdb:"name"`
	Nat               []string          `ovsdb:"nat"`
	Options           map[string]string `ovsdb:"options"`
	Policies          []string          `ovsdb:"policies"`
	Ports             []string          `ovsdb:"ports"`
	StaticRoutes      []string          `ovsdb:"static_routes"`
}

type (
	LogicalRouterPolicyAction = string
)

var (
	LogicalRouterPolicyActionAllow   LogicalRouterPolicyAction = "allow"
	LogicalRouterPolicyActionDrop    LogicalRouterPolicyAction = "drop"
	LogicalRouterPolicyActionReroute LogicalRouterPolicyAction = "reroute"
)

// LogicalRouterPolicy defines an object in Logical_Router_Policy table
type LogicalRouterPolicy struct {
	UUID        string                    `ovsdb:"_uuid"`
	Action      LogicalRouterPolicyAction `ovsdb:"action" validate:"oneof='allow' 'drop' 'reroute'"`
	ExternalIDs map[string]string         `ovsdb:"external_ids"`
	Match       string                    `ovsdb:"match"`
	Nexthop     *string                   `ovsdb:"nexthop"`
	Nexthops    []string                  `ovsdb:"nexthops"`
	Options     map[string]string         `ovsdb:"options"`
	Priority    int                       `ovsdb:"priority" validate:"min=0,max=32767"`
}

// LogicalRouterPort defines an object in Logical_Router_Port table
type LogicalRouterPort struct {
	UUID           string            `ovsdb:"_uuid"`
	Enabled        *bool             `ovsdb:"enabled"`
	ExternalIDs    map[string]string `ovsdb:"external_ids"`
	GatewayChassis []string          `ovsdb:"gateway_chassis"`
	HaChassisGroup *string           `ovsdb:"ha_chassis_group"`
	Ipv6Prefix     []string          `ovsdb:"ipv6_prefix"`
	Ipv6RaConfigs  map[string]string `ovsdb:"ipv6_ra_configs"`
	MAC            string            `ovsdb:"mac"`
	Name           string            `ovsdb:"name"`
	Networks       []string          `ovsdb:"networks" validate:"min=1"`
	Options        map[string]string `ovsdb:"options"`
	Peer           *string           `ovsdb:"peer"`
}

type (
	LogicalRouterStaticRoutePolicy = string
)

var (
	LogicalRouterStaticRoutePolicySrcIP LogicalRouterStaticRoutePolicy = "src-ip"
	LogicalRouterStaticRoutePolicyDstIP LogicalRouterStaticRoutePolicy = "dst-ip"
)

// LogicalRouterStaticRoute defines an object in Logical_Router_Static_Route table
type LogicalRouterStaticRoute struct {
	UUID        string                          `ovsdb:"_uuid"`
	BFD         *string                         `ovsdb:"bfd"`
	ExternalIDs map[string]string               `ovsdb:"external_ids"`
	IPPrefix    string                          `ovsdb:"ip_prefix"`
	Nexthop     string                          `ovsdb:"nexthop"`
	Options     map[string]string               `ovsdb:"options"`
	OutputPort  *string                         `ovsdb:"output_port"`
	Policy      *LogicalRouterStaticRoutePolicy `ovsdb:"policy" validate:"omitempty,oneof='src-ip' 'dst-ip'"`
	RouteTable  string                          `ovsdb:"route_table"`
}

type (
	MeterUnit = string
)

var (
	MeterUnitKbps  MeterUnit = "kbps"
	MeterUnitPktps MeterUnit = "pktps"
)

// Meter defines an object in Meter table
type Meter struct {
	UUID        string            `ovsdb:"_uuid"`
	Bands       []string          `ovsdb:"bands" validate:"min=1"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Fair        *bool             `ovsdb:"fair"`
	Name        string            `ovsdb:"name"`
	Unit        MeterUnit         `ovsdb:"unit" validate:"oneof='kbps' 'pktps'"`
}

type (
	MeterBandAction = string
)

var (
	MeterBandActionDrop MeterBandAction = "drop"
)

// MeterBand defines an object in Meter_Band table
type MeterBand struct {
	UUID        string            `ovsdb:"_uuid"`
	Action      MeterBandAction   `ovsdb:"action" validate:"oneof='drop'"`
	BurstSize   int               `ovsdb:"burst_size" validate:"min=0,max=4294967295"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Rate        int               `ovsdb:"rate" validate:"min=1,max=4294967295"`
}

type (
	MirrorFilter = string
	MirrorType   = string
)

var (
	MirrorFilterFromLport MirrorFilter = "from-lport"
	MirrorFilterToLport   MirrorFilter = "to-lport"
	MirrorTypeGre         MirrorType   = "gre"
	MirrorTypeErspan      MirrorType   = "erspan"
)

// Mirror defines an object in Mirror table
type Mirror struct {
	UUID        string            `ovsdb:"_uuid"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Filter      MirrorFilter      `ovsdb:"filter" validate:"oneof='from-lport' 'to-lport'"`
	Index       int               `ovsdb:"index"`
	Name        string            `ovsdb:"name"`
	Sink        string            `ovsdb:"sink"`
	Type        MirrorType        `ovsdb:"type" validate:"oneof='gre' 'erspan'"`
}

type (
	NATType = string
)

var (
	NATTypeDNAT        NATType = "dnat"
	NATTypeSNAT        NATType = "snat"
	NATTypeDNATAndSNAT NATType = "dnat_and_snat"
)

// NAT defines an object in NAT table
type NAT struct {
	UUID              string            `ovsdb:"_uuid"`
	AllowedExtIPs     *string           `ovsdb:"allowed_ext_ips"`
	ExemptedExtIPs    *string           `ovsdb:"exempted_ext_ips"`
	ExternalIDs       map[string]string `ovsdb:"external_ids"`
	ExternalIP        string            `ovsdb:"external_ip"`
	ExternalMAC       *string           `ovsdb:"external_mac"`
	ExternalPortRange string            `ovsdb:"external_port_range"`
	GatewayPort       *string           `ovsdb:"gateway_port"`
	LogicalIP         string            `ovsdb:"logical_ip"`
	LogicalPort       *string           `ovsdb:"logical_port"`
	Options           map[string]string `ovsdb:"options"`
	Type              NATType           `ovsdb:"type" validate:"oneof='dnat' 'snat' 'dnat_and_snat'"`
}

// NBGlobal defines an object in NB_Global table
type NBGlobal struct {
	UUID           string            `ovsdb:"_uuid"`
	Connections    []string          `ovsdb:"connections"`
	ExternalIDs    map[string]string `ovsdb:"external_ids"`
	HvCfg          int               `ovsdb:"hv_cfg"`
	HvCfgTimestamp int               `ovsdb:"hv_cfg_timestamp"`
	Ipsec          bool              `ovsdb:"ipsec"`
	Name           string            `ovsdb:"name"`
	NbCfg          int               `ovsdb:"nb_cfg"`
	NbCfgTimestamp int               `ovsdb:"nb_cfg_timestamp"`
	Options        map[string]string `ovsdb:"options"`
	SbCfg          int               `ovsdb:"sb_cfg"`
	SbCfgTimestamp int               `ovsdb:"sb_cfg_timestamp"`
	SSL            *string           `ovsdb:"ssl"`
}

// PortGroup defines an object in Port_Group table
type PortGroup struct {
	UUID        string            `ovsdb:"_uuid"`
	ACLs        []string          `ovsdb:"acls"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Name        string            `ovsdb:"name"`
	Ports       []string          `ovsdb:"ports"`
}

type (
	QoSAction    = string
	QoSBandwidth = string
	QoSDirection = string
)

var (
	QoSActionDSCP         QoSAction    = "dscp"
	QoSBandwidthRate      QoSBandwidth = "rate"
	QoSBandwidthBurst     QoSBandwidth = "burst"
	QoSDirectionFromLport QoSDirection = "from-lport"
	QoSDirectionToLport   QoSDirection = "to-lport"
)

// QoS defines an object in QoS table
type QoS struct {
	UUID        string            `ovsdb:"_uuid"`
	Action      map[string]int    `ovsdb:"action" validate:"dive,keys,oneof='dscp',endkeys,min=0,max=63"`
	Bandwidth   map[string]int    `ovsdb:"bandwidth" validate:"dive,keys,oneof='rate' 'burst',endkeys,min=1,max=4294967295"`
	Direction   QoSDirection      `ovsdb:"direction" validate:"oneof='from-lport' 'to-lport'"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Match       string            `ovsdb:"match"`
	Priority    int               `ovsdb:"priority" validate:"min=0,max=32767"`
}

// SSL defines an object in SSL table
type SSL struct {
	UUID            string            `ovsdb:"_uuid"`
	BootstrapCaCert bool              `ovsdb:"bootstrap_ca_cert"`
	CaCert          string            `ovsdb:"ca_cert"`
	Certificate     string            `ovsdb:"certificate"`
	ExternalIDs     map[string]string `ovsdb:"external_ids"`
	PrivateKey      string            `ovsdb:"private_key"`
	SSLCiphers      string            `ovsdb:"ssl_ciphers"`
	SSLProtocols    string            `ovsdb:"ssl_protocols"`
}

// StaticMACBinding defines an object in Static_MAC_Binding table
type StaticMACBinding struct {
	UUID               string `ovsdb:"_uuid"`
	IP                 string `ovsdb:"ip"`
	LogicalPort        string `ovsdb:"logical_port"`
	MAC                string `ovsdb:"mac"`
	OverrideDynamicMAC bool   `ovsdb:"override_dynamic_mac"`
}
