package checks

import (
	"github.com/cilium/ebpf"
)

func UpdateAmpPorts(portsmap *ebpf.Map) {

	ports := []int{
		7,     //Echo
		17,    //tftp
		19,    //Chargen
		28,    //AMP
		53,    //DNS
		62,    //ACAS
		69,    //TFTP
		80,    //UDP HTTP
		88,    //Kerberos
		111,   //RCPBind
		123,   //NTP
		137,   //NetBios
		161,   //SNMP
		389,   //CLDAP
		427,   //SLP
		443,   //UDP HTTPS
		500,   //ISAKMP
		520,   //LDAP or RIP
		751,   //Kerberos
		1108,  //ADP
		1194,  //OVPN
		1433,  //SQL
		1434,  //SQL
		1812,  //RADIUS
		1813,  //RADIUS
		1900,  //SSDP
		3283,  //Apple Remote Desktop (LMFAO APPLE MOMENT)
		3478,  //STUN
		3702,  //WSD
		3714,  //DELOS
		4387,  //PHAT
		5060,  //VoIP
		5353,  //MDNS
		5683,  //CoAP
		6881,  //BitTorrent
		8088,  //STUN
		10074, //TP 240
		11211, //Memcached
		27015, //Steam?
		27960, //Quake? Tf
		32410, //PMSSDP
		32414, //PMSSDP
		37810, //DVR
		37833, //STUN
	}

	for _, port := range ports {
		portsmap.Update(uint16(port), uint8(1), ebpf.UpdateAny) // Function to perform an action for each port
	}

}
