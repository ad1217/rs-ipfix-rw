//! Vaguely based on formatter.rs from <https://github.com/q6r/rs-ipfix/>

use ahash::{HashMap, HashMapExt};

use crate::DataRecordType;

/// mapping of (enterprise_number, information_element_identifier) -> (name, type)
pub type Formatter = HashMap<(u32, u16), (&'static str, DataRecordType)>;

macro_rules! count {
    ($_t:tt) => {
        1usize
    };
}

/// slightly nicer syntax to make a Formatter
#[macro_export]
macro_rules! formatter(
    { $(($key:expr, $id:expr) => ($string:expr, $value:ident)),+ } => {
        let mut m = Formatter::with_capacity(0usize $(+ count!($key))+);
        $(
            m.insert(($key, $id), ($string, DataRecordType::$value));
        )+
        m
    };
);

/// default information element types for no enterprise / enterprise number 0
pub fn get_default_formatter() -> Formatter {
    formatter! {
        (0, 1) => ("octetDeltaCount", UnsignedInt), // U64
        (0, 2) => ("packetDeltaCount", UnsignedInt), // U64
        (0, 4) => ("protocolIdentifier", UnsignedInt), // U8
        (0, 5) => ("ipClassOfService", UnsignedInt), // U8
        (0, 6) => ("tcpControlBits", UnsignedInt), // U8
        (0, 7) => ("sourceTransportPort", UnsignedInt), // U16
        (0, 8) => ("sourceIPv4Address", Ipv4Addr),
        (0, 9) => ("sourceIPv4PrefixLength", UnsignedInt), // U8
        (0, 10) => ("ingressInterface", UnsignedInt), // U32
        (0, 11) => ("destinationTransportPort", UnsignedInt), // U16
        (0, 12) => ("destinationIPv4Address", Ipv4Addr),
        (0, 13) => ("destinationIPv4PrefixLength", UnsignedInt), // U8
        (0, 14) => ("egressInterface", UnsignedInt), // U32
        (0, 15) => ("ipNextHopIPv4Address", Ipv4Addr),
        (0, 16) => ("bgpSourceAsNumber", UnsignedInt), // U32
        (0, 17) => ("bgpDestinationAsNumber", UnsignedInt), // U32
        (0, 18) => ("bgpNextHopIPv4Address", Ipv4Addr),
        (0, 19) => ("postMCastPacketDeltaCount", UnsignedInt), // U64
        (0, 20) => ("postMCastOctetDeltaCount", UnsignedInt), // U64
        (0, 21) => ("flowEndSysUpTime", UnsignedInt), // U32
        (0, 22) => ("flowStartSysUpTime", UnsignedInt), // U32
        (0, 23) => ("postOctetDeltaCount", UnsignedInt), // U64
        (0, 24) => ("postPacketDeltaCount", UnsignedInt), // U64
        (0, 25) => ("minimumIpTotalLength", UnsignedInt), // U64
        (0, 26) => ("maximumIpTotalLength", UnsignedInt), // U64
        (0, 27) => ("sourceIPv6Address", Ipv6Addr),
        (0, 28) => ("destinationIPv6Address", Ipv6Addr),
        (0, 29) => ("sourceIPv6PrefixLength", UnsignedInt), // U8
        (0, 30) => ("destinationIPv6PrefixLength", UnsignedInt), // U8
        (0, 31) => ("flowLabelIPv6", UnsignedInt), // U32
        (0, 32) => ("icmpTypeCodeIPv4", UnsignedInt), // U16
        (0, 33) => ("igmpType", UnsignedInt), // U8
        (0, 36) => ("flowActiveTimeout", UnsignedInt), // U16
        (0, 37) => ("flowIdleTimeout", UnsignedInt), // U16
        (0, 40) => ("exportedOctetTotalCount", UnsignedInt), // U64
        (0, 41) => ("exportedMessageTotalCount", UnsignedInt), // U64
        (0, 42) => ("exportedFlowRecordTotalCount", UnsignedInt), // U64
        (0, 44) => ("sourceIPv4Prefix", Ipv4Addr),
        (0, 45) => ("destinationIPv4Prefix", Ipv4Addr),
        (0, 46) => ("mplsTopLabelType", UnsignedInt), // U8
        (0, 47) => ("mplsTopLabelIPv4Address", Ipv4Addr),
        (0, 52) => ("minimumTTL", UnsignedInt), // U8
        (0, 53) => ("maximumTTL", UnsignedInt), // U8
        (0, 54) => ("fragmentIdentification", UnsignedInt), // U32
        (0, 55) => ("postIpClassOfService", UnsignedInt), // U8
        (0, 56) => ("sourceMacAddress", MacAddress),
        (0, 57) => ("postDestinationMacAddress", MacAddress),
        (0, 58) => ("vlanId", UnsignedInt), // U16
        (0, 59) => ("postVlanId", UnsignedInt), // U16
        (0, 60) => ("ipVersion", UnsignedInt), // U8
        (0, 61) => ("flowDirection", UnsignedInt), // U8
        (0, 62) => ("ipNextHopIPv6Address", Ipv6Addr),
        (0, 63) => ("bgpNextHopIPv6Address", Ipv6Addr),
        (0, 64) => ("ipv6ExtensionHeaders", UnsignedInt), // U32
        (0, 70) => ("mplsTopLabelStackSection", Bytes),
        (0, 71) => ("mplsLabelStackSection2", Bytes),
        (0, 72) => ("mplsLabelStackSection3", Bytes),
        (0, 73) => ("mplsLabelStackSection4", Bytes),
        (0, 74) => ("mplsLabelStackSection5", Bytes),
        (0, 75) => ("mplsLabelStackSection6", Bytes),
        (0, 76) => ("mplsLabelStackSection7", Bytes),
        (0, 77) => ("mplsLabelStackSection8", Bytes),
        (0, 78) => ("mplsLabelStackSection9", Bytes),
        (0, 79) => ("mplsLabelStackSection10", Bytes),
        (0, 80) => ("destinationMacAddress", MacAddress),
        (0, 81) => ("postSourceMacAddress", MacAddress),
        (0, 85) => ("octetTotalCount", UnsignedInt), // U64
        (0, 86) => ("packetTotalCount", UnsignedInt), // U64
        (0, 88) => ("fragmentOffset", UnsignedInt), // U16
        (0, 90) => ("mplsVpnRouteDistinguisher", Bytes),
        (0, 128) => ("bgpNextAdjacentAsNumber", UnsignedInt), // U32
        (0, 129) => ("bgpPrevAdjacentAsNumber", UnsignedInt), // U32
        (0, 130) => ("exporterIPv4Address", Ipv4Addr),
        (0, 131) => ("exporterIPv6Address", Ipv6Addr),
        (0, 132) => ("droppedOctetDeltaCount", UnsignedInt), // U64
        (0, 133) => ("droppedPacketDeltaCount", UnsignedInt), // U64
        (0, 134) => ("droppedOctetTotalCount", UnsignedInt), // U64
        (0, 135) => ("droppedPacketTotalCount", UnsignedInt), // U64
        (0, 136) => ("flowEndReason", UnsignedInt), // U8
        (0, 137) => ("commonPropertiesId", UnsignedInt), // U64
        (0, 138) => ("observationPointId", UnsignedInt), // U32
        (0, 139) => ("icmpTypeCodeIPv6", UnsignedInt), // U16
        (0, 140) => ("mplsTopLabelIPv6Address", Ipv6Addr),
        (0, 141) => ("lineCardId", UnsignedInt), // U32
        (0, 142) => ("portId", UnsignedInt), // U32
        (0, 143) => ("meteringProcessId", UnsignedInt), // U32
        (0, 144) => ("exportingProcessId", UnsignedInt), // U32
        (0, 145) => ("templateId", UnsignedInt), // U16
        (0, 146) => ("wlanChannelId", UnsignedInt), // U8
        (0, 147) => ("wlanSSID", String),
        (0, 148) => ("flowId", UnsignedInt), // U64
        (0, 149) => ("observationDomainId", UnsignedInt), // U32
        (0, 150) => ("flowStartSeconds", DateTimeSeconds),
        (0, 151) => ("flowEndSeconds", DateTimeSeconds),
        (0, 152) => ("flowStartMilliseconds", DateTimeMilliseconds),
        (0, 153) => ("flowEndMilliseconds", DateTimeMilliseconds),
        (0, 154) => ("flowStartMicroseconds", DateTimeMicroseconds),
        (0, 155) => ("flowEndMicroseconds", DateTimeMicroseconds),
        (0, 156) => ("flowStartNanoseconds", DateTimeNanoseconds),
        (0, 157) => ("flowEndNanoseconds", DateTimeNanoseconds),
        (0, 158) => ("flowStartDeltaMicroseconds", UnsignedInt), // U32
        (0, 159) => ("flowEndDeltaMicroseconds", UnsignedInt), // U32
        (0, 160) => ("systemInitTimeMilliseconds", DateTimeMilliseconds),
        (0, 161) => ("flowDurationMilliseconds", UnsignedInt), // U32
        (0, 162) => ("flowDurationMicroseconds", UnsignedInt), // U32
        (0, 163) => ("observedFlowTotalCount", UnsignedInt), // U64
        (0, 164) => ("ignoredPacketTotalCount", UnsignedInt), // U64
        (0, 165) => ("ignoredOctetTotalCount", UnsignedInt), // U64
        (0, 166) => ("notSentFlowTotalCount", UnsignedInt), // U64
        (0, 167) => ("notSentPacketTotalCount", UnsignedInt), // U64
        (0, 168) => ("notSentOctetTotalCount", UnsignedInt), // U64
        (0, 169) => ("destinationIPv6Prefix", Ipv6Addr),
        (0, 170) => ("sourceIPv6Prefix", Ipv6Addr),
        (0, 171) => ("postOctetTotalCount", UnsignedInt), // U64
        (0, 172) => ("postPacketTotalCount", UnsignedInt), // U64
        (0, 173) => ("flowKeyIndicator", UnsignedInt), // U64
        (0, 174) => ("postMCastPacketTotalCount", UnsignedInt), // U64
        (0, 175) => ("postMCastOctetTotalCount", UnsignedInt), // U64
        (0, 176) => ("icmpTypeIPv4", UnsignedInt), // U8
        (0, 177) => ("icmpCodeIPv4", UnsignedInt), // U8
        (0, 178) => ("icmpTypeIPv6", UnsignedInt), // U8
        (0, 179) => ("icmpCodeIPv6", UnsignedInt), // U8
        (0, 180) => ("udpSourcePort", UnsignedInt), // U16
        (0, 181) => ("udpDestinationPort", UnsignedInt), // U16
        (0, 182) => ("tcpSourcePort", UnsignedInt), // U16
        (0, 183) => ("tcpDestinationPort", UnsignedInt), // U16
        (0, 184) => ("tcpSequenceNumber", UnsignedInt), // U32
        (0, 185) => ("tcpAcknowledgementNumber", UnsignedInt), // U32
        (0, 186) => ("tcpWindowSize", UnsignedInt), // U16
        (0, 187) => ("tcpUrgentPointer", UnsignedInt), // U16
        (0, 188) => ("tcpHeaderLength", UnsignedInt), // U8
        (0, 189) => ("ipHeaderLength", UnsignedInt), // U8
        (0, 190) => ("totalLengthIPv4", UnsignedInt), // U16
        (0, 191) => ("payloadLengthIPv6", UnsignedInt), // U16
        (0, 192) => ("ipTTL", UnsignedInt), // U8
        (0, 193) => ("nextHeaderIPv6", UnsignedInt), // U8
        (0, 194) => ("mplsPayloadLength", UnsignedInt), // U32
        (0, 195) => ("ipDiffServCodePoint", UnsignedInt), // U8
        (0, 196) => ("ipPrecedence", UnsignedInt), // U8
        (0, 197) => ("fragmentFlags", UnsignedInt), // U8
        (0, 198) => ("octetDeltaSumOfSquares", UnsignedInt), // U64
        (0, 199) => ("octetTotalSumOfSquares", UnsignedInt), // U64
        (0, 200) => ("mplsTopLabelTTL", UnsignedInt), // U8
        (0, 201) => ("mplsLabelStackLength", UnsignedInt), // U32
        (0, 202) => ("mplsLabelStackDepth", UnsignedInt), // U32
        (0, 203) => ("mplsTopLabelExp", UnsignedInt), // U8
        (0, 204) => ("ipPayloadLength", UnsignedInt), // U32
        (0, 205) => ("udpMessageLength", UnsignedInt), // U16
        (0, 206) => ("isMulticast", UnsignedInt), // U8
        (0, 207) => ("ipv4IHL", UnsignedInt), // U8
        (0, 208) => ("ipv4Options", UnsignedInt), // U32
        (0, 209) => ("tcpOptions", UnsignedInt), // U64
        (0, 210) => ("paddingOctets", Bytes),
        (0, 211) => ("collectorIPv4Address", Ipv4Addr),
        (0, 212) => ("collectorIPv6Address", Ipv6Addr),
        (0, 213) => ("exportInterface", UnsignedInt), // U32
        (0, 214) => ("exportProtocolVersion", UnsignedInt), // U8
        (0, 215) => ("exportTransportProtocol", UnsignedInt), // U8
        (0, 216) => ("collectorTransportPort", UnsignedInt), // U16
        (0, 217) => ("exporterTransportPort", UnsignedInt), // U16
        (0, 218) => ("tcpSynTotalCount", UnsignedInt), // U64
        (0, 219) => ("tcpFinTotalCount", UnsignedInt), // U64
        (0, 220) => ("tcpRstTotalCount", UnsignedInt), // U64
        (0, 221) => ("tcpPshTotalCount", UnsignedInt), // U64
        (0, 222) => ("tcpAckTotalCount", UnsignedInt), // U64
        (0, 223) => ("tcpUrgTotalCount", UnsignedInt), // U64
        (0, 224) => ("ipTotalLength", UnsignedInt), // U64
        (0, 237) => ("postMplsTopLabelExp", UnsignedInt), // U8
        (0, 238) => ("tcpWindowScale", UnsignedInt) // U16
    }
}
