  Frame: Number = 8, Captured Frame Length = 137, MediaType = ETHERNET
- Ethernet: Etype = Internet IP (IPv4),DestinationAddress:[0A-00-27-00-00-00],SourceAddress:[08-00-27-25-A9-6E]
  - DestinationAddress: 0A0027 000000 [0A-00-27-00-00-00]
     Rsv: (000010..)
     UL:  (......1.) Locally Administered Address
     IG:  (.......0) Individual address (unicast)
  - SourceAddress: CADMUS COMPUTER SYSTEMS 25A96E [08-00-27-25-A9-6E]
     Rsv: (000010..)
     UL:  (......0.) Universally Administered Address
     IG:  (.......0) Individual address (unicast)
    EthernetType: Internet IP (IPv4), 2048(0x800)
- Ipv4: Src = 192.168.56.101, Dest = 192.168.56.1, Next Protocol = TCP, Packet ID = 5250, Total IP Length = 123
  - Versions: IPv4, Internet Protocol; Header Length = 20
     Version:      (0100....) IPv4, Internet Protocol
     HeaderLength: (....0101) 20 bytes (0x5)
  - DifferentiatedServicesField: DSCP: 0, ECN: 0
     DSCP: (000000..) Differentiated services codepoint 0
     ECT:  (......0.) ECN-Capable Transport not set
     CE:   (.......0) ECN-CE not set
    TotalLength: 123 (0x7B)
    Identification: 5250 (0x1482)
  - FragmentFlags: 16384 (0x4000)
     Reserved: (0...............)
     DF:       (.1..............) Do not fragment
     MF:       (..0.............) This is the last fragment
     Offset:   (...0000000000000) 0
    TimeToLive: 64 (0x40)
    NextProtocol: TCP, 6(0x6)
    Checksum: 13380 (0x3444)
    SourceAddress: 192.168.56.101
    DestinationAddress: 192.168.56.1
- Tcp: [ReTransmit #7]Flags=...AP..., SrcPort=53866, DstPort=HTTP(80), PayloadLen=83, Seq=2794130671 - 2794130754, Ack=2959935579, Win=115 (scale factor 0x7) = 14720
    SrcPort: 53866
    DstPort: HTTP(80)
    SequenceNumber: 2794130671 (0xA68B0CEF)
    AcknowledgementNumber: 2959935579 (0xB06D085B)
  - DataOffset: 80 (0x50)
     DataOffset: (0101....) 20 bytes
     Reserved:   (....000.)
     NS:         (.......0) Nonce Sum not significant
  + Flags: ...AP...
    Window: 115 (scale factor 0x7) = 14720
    Checksum: 0xE839, Good
    UrgentPointer: 0 (0x0)
    RetransmitPayload: Binary Large Object (83 Bytes)

