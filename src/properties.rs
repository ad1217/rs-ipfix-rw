//! Vaguely based on formatter.rs from <https://github.com/q6r/rs-ipfix/>

use std::collections::HashMap;

use crate::DataRecordType;

/// mapping of field_id -> name, type
pub type FieldFormatter = HashMap<u16, (&'static str, DataRecordType)>;

/// mapping of enterprise_number -> FieldFormatters
pub type EnterpriseFormatter = HashMap<u32, FieldFormatter>;

/// create a map of field id => name, type
#[macro_export]
macro_rules! field_type(
    { $($key:expr => ($string:expr, $value:ident)),+ } => {
        {
        let mut m = FieldFormatter::default();
            $(
                m.insert($key, ($string, DataRecordType::$value));
            )+
            m
        }
    };
);

pub fn get_default_enterprise() -> EnterpriseFormatter {
    let mut e = HashMap::new();
    e.insert(0, get_default_types());
    e
}

/// default field_types for enterprise number 0
pub fn get_default_types() -> FieldFormatter {
    field_type! {
        1 => ("octetDeltaCount", UnsignedInt), // U64
        2 => ("packetDeltaCount", UnsignedInt), // U64
        4 => ("protocolIdentifier", UnsignedInt), // U8
        5 => ("ipClassOfService", UnsignedInt), // U8
        6 => ("tcpControlBits", UnsignedInt), // U8
        7 => ("sourceTransportPort", UnsignedInt), // U16
        8 => ("sourceIPv4Address", Ipv4Addr),
        9 => ("sourceIPv4PrefixLength", UnsignedInt), // U8
        10 => ("ingressInterface", UnsignedInt), // U32
        11 => ("destinationTransportPort", UnsignedInt), // U16
        12 => ("destinationIPv4Address", Ipv4Addr),
        13 => ("destinationIPv4PrefixLength", UnsignedInt), // U8
        14 => ("egressInterface", UnsignedInt), // U32
        15 => ("ipNextHopIPv4Address", Ipv4Addr),
        16 => ("bgpSourceAsNumber", UnsignedInt), // U32
        17 => ("bgpDestinationAsNumber", UnsignedInt), // U32
        18 => ("bgpNextHopIPv4Address", Ipv4Addr),
        19 => ("postMCastPacketDeltaCount", UnsignedInt), // U64
        20 => ("postMCastOctetDeltaCount", UnsignedInt), // U64
        21 => ("flowEndSysUpTime", UnsignedInt), // U32
        22 => ("flowStartSysUpTime", UnsignedInt), // U32
        23 => ("postOctetDeltaCount", UnsignedInt), // U64
        24 => ("postPacketDeltaCount", UnsignedInt), // U64
        25 => ("minimumIpTotalLength", UnsignedInt), // U64
        26 => ("maximumIpTotalLength", UnsignedInt), // U64
        27 => ("sourceIPv6Address", Ipv6Addr),
        28 => ("destinationIPv6Address", Ipv6Addr),
        29 => ("sourceIPv6PrefixLength", UnsignedInt), // U8
        30 => ("destinationIPv6PrefixLength", UnsignedInt), // U8
        31 => ("flowLabelIPv6", UnsignedInt), // U32
        32 => ("icmpTypeCodeIPv4", UnsignedInt), // U16
        33 => ("igmpType", UnsignedInt), // U8
        36 => ("flowActiveTimeout", UnsignedInt), // U16
        37 => ("flowIdleTimeout", UnsignedInt), // U16
        40 => ("exportedOctetTotalCount", UnsignedInt), // U64
        41 => ("exportedMessageTotalCount", UnsignedInt), // U64
        42 => ("exportedFlowRecordTotalCount", UnsignedInt), // U64
        44 => ("sourceIPv4Prefix", Ipv4Addr),
        45 => ("destinationIPv4Prefix", Ipv4Addr),
        46 => ("mplsTopLabelType", UnsignedInt), // U8
        47 => ("mplsTopLabelIPv4Address", Ipv4Addr),
        52 => ("minimumTTL", UnsignedInt), // U8
        53 => ("maximumTTL", UnsignedInt), // U8
        54 => ("fragmentIdentification", UnsignedInt), // U32
        55 => ("postIpClassOfService", UnsignedInt), // U8
        56 => ("sourceMacAddress", MacAddress),
        57 => ("postDestinationMacAddress", MacAddress),
        58 => ("vlanId", UnsignedInt), // U16
        59 => ("postVlanId", UnsignedInt), // U16
        60 => ("ipVersion", UnsignedInt), // U8
        61 => ("flowDirection", UnsignedInt), // U8
        62 => ("ipNextHopIPv6Address", Ipv6Addr),
        63 => ("bgpNextHopIPv6Address", Ipv6Addr),
        64 => ("ipv6ExtensionHeaders", UnsignedInt), // U32
        70 => ("mplsTopLabelStackSection", Bytes),
        71 => ("mplsLabelStackSection2", Bytes),
        72 => ("mplsLabelStackSection3", Bytes),
        73 => ("mplsLabelStackSection4", Bytes),
        74 => ("mplsLabelStackSection5", Bytes),
        75 => ("mplsLabelStackSection6", Bytes),
        76 => ("mplsLabelStackSection7", Bytes),
        77 => ("mplsLabelStackSection8", Bytes),
        78 => ("mplsLabelStackSection9", Bytes),
        79 => ("mplsLabelStackSection10", Bytes),
        80 => ("destinationMacAddress", MacAddress),
        81 => ("postSourceMacAddress", MacAddress),
        85 => ("octetTotalCount", UnsignedInt), // U64
        86 => ("packetTotalCount", UnsignedInt), // U64
        88 => ("fragmentOffset", UnsignedInt), // U16
        90 => ("mplsVpnRouteDistinguisher", Bytes),
        128 => ("bgpNextAdjacentAsNumber", UnsignedInt), // U32
        129 => ("bgpPrevAdjacentAsNumber", UnsignedInt), // U32
        130 => ("exporterIPv4Address", Ipv4Addr),
        131 => ("exporterIPv6Address", Ipv6Addr),
        132 => ("droppedOctetDeltaCount", UnsignedInt), // U64
        133 => ("droppedPacketDeltaCount", UnsignedInt), // U64
        134 => ("droppedOctetTotalCount", UnsignedInt), // U64
        135 => ("droppedPacketTotalCount", UnsignedInt), // U64
        136 => ("flowEndReason", UnsignedInt), // U8
        137 => ("commonPropertiesId", UnsignedInt), // U64
        138 => ("observationPointId", UnsignedInt), // U32
        139 => ("icmpTypeCodeIPv6", UnsignedInt), // U16
        140 => ("mplsTopLabelIPv6Address", Ipv6Addr),
        141 => ("lineCardId", UnsignedInt), // U32
        142 => ("portId", UnsignedInt), // U32
        143 => ("meteringProcessId", UnsignedInt), // U32
        144 => ("exportingProcessId", UnsignedInt), // U32
        145 => ("templateId", UnsignedInt), // U16
        146 => ("wlanChannelId", UnsignedInt), // U8
        147 => ("wlanSSID", String),
        148 => ("flowId", UnsignedInt), // U64
        149 => ("observationDomainId", UnsignedInt), // U32
        150 => ("flowStartSeconds", DateTimeSeconds),
        151 => ("flowEndSeconds", DateTimeSeconds),
        152 => ("flowStartMilliseconds", DateTimeMilliseconds),
        153 => ("flowEndMilliseconds", DateTimeMilliseconds),
        154 => ("flowStartMicroseconds", DateTimeMicroseconds),
        155 => ("flowEndMicroseconds", DateTimeMicroseconds),
        156 => ("flowStartNanoseconds", DateTimeNanoseconds),
        157 => ("flowEndNanoseconds", DateTimeNanoseconds),
        158 => ("flowStartDeltaMicroseconds", UnsignedInt), // U32
        159 => ("flowEndDeltaMicroseconds", UnsignedInt), // U32
        160 => ("systemInitTimeMilliseconds", DateTimeMilliseconds),
        161 => ("flowDurationMilliseconds", UnsignedInt), // U32
        162 => ("flowDurationMicroseconds", UnsignedInt), // U32
        163 => ("observedFlowTotalCount", UnsignedInt), // U64
        164 => ("ignoredPacketTotalCount", UnsignedInt), // U64
        165 => ("ignoredOctetTotalCount", UnsignedInt), // U64
        166 => ("notSentFlowTotalCount", UnsignedInt), // U64
        167 => ("notSentPacketTotalCount", UnsignedInt), // U64
        168 => ("notSentOctetTotalCount", UnsignedInt), // U64
        169 => ("destinationIPv6Prefix", Ipv6Addr),
        170 => ("sourceIPv6Prefix", Ipv6Addr),
        171 => ("postOctetTotalCount", UnsignedInt), // U64
        172 => ("postPacketTotalCount", UnsignedInt), // U64
        173 => ("flowKeyIndicator", UnsignedInt), // U64
        174 => ("postMCastPacketTotalCount", UnsignedInt), // U64
        175 => ("postMCastOctetTotalCount", UnsignedInt), // U64
        176 => ("icmpTypeIPv4", UnsignedInt), // U8
        177 => ("icmpCodeIPv4", UnsignedInt), // U8
        178 => ("icmpTypeIPv6", UnsignedInt), // U8
        179 => ("icmpCodeIPv6", UnsignedInt), // U8
        180 => ("udpSourcePort", UnsignedInt), // U16
        181 => ("udpDestinationPort", UnsignedInt), // U16
        182 => ("tcpSourcePort", UnsignedInt), // U16
        183 => ("tcpDestinationPort", UnsignedInt), // U16
        184 => ("tcpSequenceNumber", UnsignedInt), // U32
        185 => ("tcpAcknowledgementNumber", UnsignedInt), // U32
        186 => ("tcpWindowSize", UnsignedInt), // U16
        187 => ("tcpUrgentPointer", UnsignedInt), // U16
        188 => ("tcpHeaderLength", UnsignedInt), // U8
        189 => ("ipHeaderLength", UnsignedInt), // U8
        190 => ("totalLengthIPv4", UnsignedInt), // U16
        191 => ("payloadLengthIPv6", UnsignedInt), // U16
        192 => ("ipTTL", UnsignedInt), // U8
        193 => ("nextHeaderIPv6", UnsignedInt), // U8
        194 => ("mplsPayloadLength", UnsignedInt), // U32
        195 => ("ipDiffServCodePoint", UnsignedInt), // U8
        196 => ("ipPrecedence", UnsignedInt), // U8
        197 => ("fragmentFlags", UnsignedInt), // U8
        198 => ("octetDeltaSumOfSquares", UnsignedInt), // U64
        199 => ("octetTotalSumOfSquares", UnsignedInt), // U64
        200 => ("mplsTopLabelTTL", UnsignedInt), // U8
        201 => ("mplsLabelStackLength", UnsignedInt), // U32
        202 => ("mplsLabelStackDepth", UnsignedInt), // U32
        203 => ("mplsTopLabelExp", UnsignedInt), // U8
        204 => ("ipPayloadLength", UnsignedInt), // U32
        205 => ("udpMessageLength", UnsignedInt), // U16
        206 => ("isMulticast", UnsignedInt), // U8
        207 => ("ipv4IHL", UnsignedInt), // U8
        208 => ("ipv4Options", UnsignedInt), // U32
        209 => ("tcpOptions", UnsignedInt), // U64
        210 => ("paddingOctets", Bytes),
        211 => ("collectorIPv4Address", Ipv4Addr),
        212 => ("collectorIPv6Address", Ipv6Addr),
        213 => ("exportInterface", UnsignedInt), // U32
        214 => ("exportProtocolVersion", UnsignedInt), // U8
        215 => ("exportTransportProtocol", UnsignedInt), // U8
        216 => ("collectorTransportPort", UnsignedInt), // U16
        217 => ("exporterTransportPort", UnsignedInt), // U16
        218 => ("tcpSynTotalCount", UnsignedInt), // U64
        219 => ("tcpFinTotalCount", UnsignedInt), // U64
        220 => ("tcpRstTotalCount", UnsignedInt), // U64
        221 => ("tcpPshTotalCount", UnsignedInt), // U64
        222 => ("tcpAckTotalCount", UnsignedInt), // U64
        223 => ("tcpUrgTotalCount", UnsignedInt), // U64
        224 => ("ipTotalLength", UnsignedInt), // U64
        237 => ("postMplsTopLabelExp", UnsignedInt), // U8
        238 => ("tcpWindowScale", UnsignedInt) // U16
    }
}
