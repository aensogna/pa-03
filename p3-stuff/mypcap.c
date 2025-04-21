/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022

    Implemented By:     Abigail Ensogna
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"
#include "netdb.h"
/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE *pcapInput = NULL; // The input PCAP file
bool bytesOK;           // Does the capturer's byte ordering same as mine?
              // Affects the global PCAP header and each packet's header

bool microSec; // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double baseTime; // capturing time of the very 1st packet in this file
bool baseTimeSet = false;

int NORMMAGIC = 0xa1b2c3d4;
int SWAPMAGIC = 0xd4c3b2a1;
int NANOMAGIC = 0xa1b23c4d;

arpmap_t myARPmap[MAXARPMAP]; // List of my IPs, their MACs
int mapSize = 0;              // Number of mapping pairs read into above array
FILE *pcapOutput = NULL;
int ipID = 1000;

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */
/*-------------------------------------------------------------------------*/
void
errorExit (char *str)
{
  if (str)
    puts (str);
  if (pcapInput)
    fclose (pcapInput);
  exit (EXIT_FAILURE);
}

/*-------------------------------------------------------------------------*/
void
cleanUp ()
{
  if (pcapInput)
    fclose (pcapInput);
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname'
    and read its global header into buffer 'p'
    Side effects:
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int
readPCAPhdr (char *fname, pcap_hdr_t *p)
{
  if (fname == NULL || p == NULL)
    {
      return -1;
    }
  // Read packet header
  pcapInput = fopen (fname, "r");
  fread (p, sizeof (pcap_hdr_t), 1, pcapInput);

  // Determine byte ordering and time measurement
  if (p->magic_number == NORMMAGIC)
    {
      bytesOK = true;
      microSec = true;
    }
  else if (p->magic_number == NANOMAGIC)
    {
      bytesOK = true;
      microSec = false;
    }
  else if (p->magic_number == SWAPMAGIC)
    {
      bytesOK = false;
      microSec = true;
    }
  else
    {
      bytesOK = false;
      microSec = false;
    }

  if (!bytesOK)
    {
      // Swap ordering if necessary
      p->version_major = htons (p->version_major);
      p->version_minor = htons (p->version_minor);
      p->thiszone = htons (p->thiszone);
      p->sigfigs = htons (p->sigfigs);
      p->snaplen = htons (p->snaplen);
      p->network = htons (p->network);
    }
  return 0;

  // Missing Code Here

  // Determine the capturer's byte ordering
  // Issue: majic_number could also be 0xa1b23c4D to indicate nano-second
  // resolution instead of microseconds. This affects the interpretation
  // of the ts_usec field in each packet's header.

  // Missing Code Here
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void
printPCAPhdr (const pcap_hdr_t *p)
{
  printf ("magic number %X\n", p->magic_number);
  printf ("major version %d\n", p->version_major);
  printf ("minor version %d\n", p->version_minor);
  printf ("GMT to local correction %d seconds\n", p->thiszone);
  printf ("accuracy of timestamps %d\n", p->sigfigs);
  printf ("Cut-off max length of captured packets %d\n", p->snaplen);
  printf ("data link type %d\n", p->network);
  // Missing Code Here
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame)
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload

    If this is the very first packet from the PCAP file, set the baseTime

    Returns true on success, or false on failure for any reason */

bool
getNextPacket (packetHdr_t *p, uint8_t ethFrame[])
{
  // Check for incoming NULL pointers
  if (p == NULL || ethFrame == NULL)
    {
      return false;
    }
  // Read the header of the next paket in the PCAP file
  if (fread (p, sizeof (packetHdr_t), 1, pcapInput) == 0)
    {
      return false;
    }

  // Did the capturer use a different
  // byte-ordering than mine (as determined by the magic number)?
  if (!bytesOK)
    {
      // reorder the bytes of the fields in this packet header
      p->ts_sec = htons (p->ts_sec);
      p->ts_usec = htons (p->ts_usec);
      p->incl_len = htons (p->incl_len);
      p->orig_len = htons (p->orig_len);
    }
  // Read the 'incl_len' bytes from the PCAP file into the ethFrame[]
  int read = fread (ethFrame, sizeof (uint8_t), p->incl_len, pcapInput);
  if (read != p->incl_len)
    {
      return false;
    }

  // If necessary, set the baseTime .. Pay attention to possibility of nano
  // second time precision (instead of micro seconds )
  if (!baseTimeSet)
    {
      double divisor;

      if (microSec)
        divisor = 1000000;
      else
        divisor = 1000000000;

      baseTime = p->ts_sec + (p->ts_usec / divisor);
      baseTimeSet = true;
    }

  return true;
}

/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */

void
printPacketMetaData (const packetHdr_t *p)
{
  // Get packet capture time
  double divisor;
  if (microSec)
    divisor = 1000000;
  else
    divisor = 1000000000;
  double time = p->ts_sec + (p->ts_usec / divisor);

  printf ("%14.6f%7d / %6d ", time - baseTime, p->orig_len, p->incl_len);
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */

void
printPacket (const etherHdr_t *frPtr)
{
  char ipBuf[MAXIPv4ADDRLEN], macBuf[MAXMACADDRLEN];
  uint16_t ethType = htons (frPtr->eth_type);
  // If this is NOT an IPv4 packet, print Source/Destination MAC addresses
  switch (ethType)
    {
    case PROTO_ARP: // Print ARP message
      macToStr (frPtr->eth_srcMAC, macBuf);
      printf ("%-21s", macBuf);
      macToStr (frPtr->eth_dstMAC, macBuf);
      printf ("%-17s    ", macBuf);
      printARPinfo ((arpMsg_t *)(frPtr + 1));
      // Missing Code Here ... calls printARPinfo()
      return;
    case PROTO_IPv4: // Print IP datagram and upper protocols
      ipv4Hdr_t *ip = (ipv4Hdr_t *)(frPtr + 1);
      ipToStr (ip->ip_srcIP, ipBuf);
      printf ("%-21s", ipBuf);
      ipToStr (ip->ip_dstIP, ipBuf);
      printf ("%-21s", ipBuf);
      printIPinfo (ip);
      // print Source/Destination IP addresses
      // Missing Code Here ... calls printIPinfo()
      return;
    default:
      macToStr (frPtr->eth_srcMAC, macBuf);
      printf ("%-21s", macBuf);
      macToStr (frPtr->eth_dstMAC, macBuf);
      printf ("%-17s    ", macBuf);
      printf ("Protocol %hu Not Supported Yet", ethType);
      return;
    }
}
/*-------------------------------------------------------------------------*/
/* Print ARP messages */
void
printARPinfo (const arpMsg_t *p)
{
  // Missing Code Here
  char macBuf[MAXMACADDRLEN], ipBuf[MAXIPv4ADDRLEN];
  printf ("%-8s ", "ARP");
  uint16_t op = htons (p->arp_oper);
  switch (op)
    {
    case ARPREQUEST:
      printf ("Who has %s ? ", ipToStr (p->arp_tpa, ipBuf));
      printf ("Tell %s", ipToStr (p->arp_spa, ipBuf));
      break;
    case ARPREPLY:
      printf ("%s is at %s", ipToStr (p->arp_spa, ipBuf),
              macToStr (p->arp_sha, macBuf));
      break;
    default:
      printf ("Invalid ARP Operation %4x", op);
      break;
    }
}
/*-------------------------------------------------------------------------*/
/* Print IP datagram and upper protocols
Recall that all multi-byte data is in Network-Byte-Ordering
*/
void
printIPinfo (const ipv4Hdr_t *q)
{
  void *nextHdr;
  icmpHdr_t *ic;
  unsigned ipHdrLen, ipPayLen, dataLen = 0, optLen = 0;
  // 'dataLen' is the number of bytes in the payload of the encapsulated
  // protocol without its header. For example, it could be the number of bytes
  // in the payload of the encapsulated ICMP message
  // Calculate the IP header length in bytes
  // Calculate the IP payload length (total length - header length)
  ipHdrLen = (q->ip_verHlen & 0x0F) * 4;
  ipPayLen = htons (q->ip_totLen) - ipHdrLen;

  optLen = ipHdrLen - sizeof (ipv4Hdr_t); // The minimup IP header is 20 bytes
  nextHdr = (void *)((uint8_t *)q + ipHdrLen);

  // Calculate the IP header options length in bytes
  switch (q->ip_proto)
    {
    case PROTO_ICMP:
      printf ("%-8s ", "ICMP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned icmpHdrLen = printICMPinfo ((icmpHdr_t *)nextHdr);
      dataLen = ipPayLen - icmpHdrLen;
      // Print the details of the ICMP message by calling printICMPinfo()
      // Compute 'dataLen' : the length of the data section inside the ICMP
      // message
      break;
    case PROTO_TCP:
      printf ("%-8s ", "TCP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned tcpHdrLen = printTCPinfo ((tcpHdr_t *)nextHdr);
      dataLen = ipPayLen - tcpHdrLen;
      // Leave dataLen as Zero for now
      break;
    case PROTO_UDP:
      printf ("%-8s ", "UDP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned udpHdrLen = printUDPinfo ((udpHdr_t *)nextHdr);
      dataLen = ipPayLen - udpHdrLen;
      // Leave dataLen as Zero for now
      break;
    default:
      printf ("%8x %s", q->ip_proto, "Protocol is Not Supported Yet");
      return;
    }
  printf (" AppData=%5u", dataLen);
}
/*-------------------------------------------------------------------------*/
/* Print the ICMP info
Recall that all multi-byte data is in Network-Byte-Ordering
Returns length of the ICMP header in bytes
*/
unsigned
printICMPinfo (const icmpHdr_t *p)
{
  unsigned icmpHdrLen = sizeof (icmpHdr_t);
  uint16_t *id, *seqNum;
  id = (uint16_t *)p->icmp_line2;
  seqNum = (uint16_t *)(id + 1);
  printf (" ICMP_HDR{ ");
  switch (p->icmp_type)
    {
    case ICMP_ECHO_REPLY: // Validate that code is 0
      // Verify code == 0,
      // if yes print "Echo Reply :id=....., seq=....."
      // Otherwise printf( "Echo Reply : %19s %3d" , "INVALID Code:" , ....) ;
      if (p->icmp_code == 0)
        {
          printf ("Echo Reply   :id=%5d, seq=%5d", htons (*id),
                  htons (*seqNum));
        }
      else
        {
          printf ("Echo Reply   : %19s %3d", "INVALID Code:", p->icmp_code);
        }
      break;
    case ICMP_ECHO_REQUEST: // Validate that code is 0
      // Verify code == 0,
      // if yes print "Echo Request :id=....., seq=....."
      // Otherwise printf( "Echo Request : %19s %3d" , "INVALID Code:" , ....
      // );
      if (p->icmp_code == 0)
        {
          printf ("Echo Request :id=%5d, seq=%5d", htons (*id),
                  htons (*seqNum));
        }
      else
        {
          printf ("Echo Request : %19s %3d", "INVALID Code:", p->icmp_code);
        }
      break;
    default:
      printf ("Type %3d , code %3d Not Yet Supported", p->icmp_type,
              p->icmp_code);
    }
  printf ("}");
  return icmpHdrLen;
}

/*  Project 2  */
unsigned
printTCPinfo (const tcpHdr_t *p)
{
  const char *protocol = "tcp";
  unsigned tcpHdrLen = sizeof (tcpHdr_t);
  struct servent *srcServ, *dstServ;
  char *srcName, *dstName;
  char *ackStr, *pshStr, *rstStr, *synStr, *finStr;
  unsigned hlen, optLen, src, dst, seqNum, ackNum, rwnd;
  bool ack, psh, rst, syn, fin;

  src = htons (p->tcp_srcPort);
  dst = htons (p->tcp_dstPort);
  seqNum = htonl (p->tcp_seqNum);
  ackNum = htonl (p->tcp_ackNum);
  rwnd = htons (p->tcp_window);

  ack = (htons (p->tcp_hlen_reserved_flags) & (1 << 4));
  if (ack)
    {
      ackStr = "ACK ";
    }
  else
    {
      ackStr = "    ";
    }
  psh = (htons (p->tcp_hlen_reserved_flags) & (1 << 3));
  if (psh)
    {
      pshStr = "PSH ";
    }
  else
    {
      pshStr = "    ";
    }
  rst = (htons (p->tcp_hlen_reserved_flags) & (1 << 2));
  if (rst)
    {
      rstStr = "RST ";
    }
  else
    {
      rstStr = "    ";
    }
  syn = (htons (p->tcp_hlen_reserved_flags) & (1 << 1));
  if (syn)
    {
      synStr = "SYN ";
    }
  else
    {
      synStr = "    ";
    }
  fin = (htons (p->tcp_hlen_reserved_flags) & 1);
  if (fin)
    {
      finStr = "FIN ";
    }
  else
    {
      finStr = "    ";
    }

  hlen = ((htons (p->tcp_hlen_reserved_flags) & 0xF000) * 4) >> 12;
  optLen = hlen - sizeof (tcpHdr_t);

  printf (" TCPhdr=%2u (Options %2u bytes) ", hlen, optLen);

  srcServ = getservbyport (ntohs (src), protocol);
  if (srcServ)
    {
      srcName = srcServ->s_name;
    }
  else
    {
      srcName = "*** ";
    }
  printf ("Port %5u (%7s) -> ", src, srcName);

  dstServ = getservbyport (ntohs (dst), protocol);
  if (dstServ)
    {
      dstName = dstServ->s_name;
    }
  else
    {
      dstName = "*** ";
    }
  printf ("%5u (%7s) ", dst, dstName);

  printf ("[%s%s%s%s%s] Seq=%10u ", synStr, pshStr, ackStr, finStr, rstStr,
          seqNum);

  if (ackNum)
    {
      printf ("Ack=%10u ", ackNum);
    }
  else
    {
      printf ("               ");
    }

  printf ("Rwnd=%5hu", rwnd);

  return tcpHdrLen + optLen;
}

unsigned
printUDPinfo (const udpHdr_t *p)
{
  unsigned udpHdrLen = sizeof (udpHdr_t);
  struct servent *srcServ, *dstServ;
  unsigned src, dst, len, cksum;
  const char *protocol = "udp";
  char *srcName, *dstName;

  src = htons (p->udp_srcPort);
  dst = htons (p->udp_dstPort);
  len = htons (p->udp_len);
  cksum = htons (p->udp_cksum);

  printf (" UDP %5u Bytes. ", len);

  srcServ = getservbyport (htons (src), protocol);
  if (srcServ)
    {
      srcName = srcServ->s_name;
    }
  else
    {
      srcName = "*** ";
    }

  printf ("Port %5u (%7s) -> ", src, srcName);

  dstServ = getservbyport (htons (dst), protocol);
  if (dstServ)
    {
      dstName = dstServ->s_name;
    }
  else
    {
      dstName = "*** ";
    }

  printf ("%5u (%7s) ", dst, dstName);
  return udpHdrLen;
}

/*-------------------------------------------------------------------------*/
/* Project 3*/
/*-------------------------------------------------------------------------*/

/*
You have just read a packet from the input PCAP file where
"pktHdr" points at its packet header, and its captured Ethernet frame is in
ethFrame[].

You shall print the
  destination MAC of this packet,
  and whether that address is one of yours.

If this packet destination MAC does NOT target your machine,
  Simply return from here.
  - Do NOT even copy it to the output PCAP file. -

Otherwise:
  Respond only to an incoming ARP Request or proper ICMP Echo Request targeting
your machine as follows: Copy the request packet (header + Ethernet frame) as
is, followed by your reply packet (header + Ethernet frame) to the output PCAP
file. For your ICMP Echo reply packet: the starting IP Identification must be
1000 (in decimal), then incremented by 1 for successive IP datagrams you
generate to the output. The IP flags should indicate "Do Not Fragment"
*/
void
processRequestPacket (packetHdr_t *pktHdr, uint8_t ethFrame[])
{
  uint8_t macBuf[MAXMACADDRLEN];

  char temp[MAXMACADDRLEN]; 
  char temp2[MAXIPv4ADDRLEN]; 
  const etherHdr_t *frPtr = (const etherHdr_t *)ethFrame;
  macToStr (frPtr->eth_dstMAC, macBuf);
  printf ("      %-21s", macBuf);

  if (!myMAC (macBuf))
    {
      printf ("   is NOT mine");
      return;
    }

  printf ("   is mine");

  //   if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput)
  //     != sizeof (packetHdr_t)) // Copy Header
  //   {
  //     errorExit ("Unsuccessful copy of packet header.");
  //   }
  // if (fwrite (frPtr, 1, pktHdr->incl_len, pcapOutput)
  //     != pktHdr->incl_len) // Copy data
  //   {
  //     errorExit ("Unsuccessful copy of packet data.");
  //   }

  if (htons (frPtr->eth_type) == PROTO_ARP)
    {
      arpMsg_t *arpMsg = (arpMsg_t *)(frPtr + 1);
      uint8_t *mac;
      if (myIP (arpMsg->arp_tpa, &mac)
          && htons (arpMsg->arp_oper) == ARPREQUEST)
        {
          uint8_t *ptr;
          if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput)
              != sizeof (packetHdr_t)) // Copy Header
            {
              errorExit ("Unsuccessful copy of packet header.");
            }
          if (fwrite (frPtr, 1, pktHdr->incl_len, pcapOutput)
              != pktHdr->incl_len) // Copy data
            {
              errorExit ("Unsuccessful copy of packet data.");
            }

          // Structure to hold packet data
          uint8_t replyFrame[MAXFRAMESZ + 30000];
          memset (replyFrame, 0, MAXFRAMESZ + 30000);
          etherHdr_t *replyPtr = (etherHdr_t *)replyFrame;

          // Reply packet header
          packetHdr_t newPktHdr;
          newPktHdr.ts_sec = pktHdr->ts_sec;
          newPktHdr.ts_usec = pktHdr->ts_usec + 30;
          newPktHdr.orig_len = pktHdr->orig_len;
          newPktHdr.incl_len = pktHdr->incl_len;

          // Write the header
          if (fwrite (&newPktHdr, 1, sizeof (packetHdr_t), pcapOutput)
              != sizeof (packetHdr_t))
            {
              errorExit ("Unsuccessful copy of packet header.");
            }

          // Make the new ethernet header
          etherHdr_t newEthHdr;
          memcpy (newEthHdr.eth_srcMAC, mac, ETHERNETHLEN);
          memcpy (newEthHdr.eth_dstMAC, frPtr->eth_srcMAC, ETHERNETHLEN);
          newEthHdr.eth_type = ntohs (PROTO_ARP);

          // Copy into data blob
          memcpy (replyFrame, &newEthHdr, sizeof (etherHdr_t));

          // Make new arp reply message
          arpMsg_t newArp;
          newArp.arp_htype = arpMsg->arp_htype;
          newArp.arp_ptype = arpMsg->arp_ptype;
          newArp.arp_hlen = arpMsg->arp_hlen;
          newArp.arp_plen = arpMsg->arp_plen;
          newArp.arp_oper = ntohs (ARPREPLY);
          memcpy (newArp.arp_sha, mac, ETHERNETHLEN);
          memcpy (newArp.arp_tha, arpMsg->arp_sha, ETHERNETHLEN);
          newArp.arp_spa = arpMsg->arp_tpa;
          newArp.arp_tpa = arpMsg->arp_spa;

          // Copy into data blob
          memcpy (replyFrame + sizeof (etherHdr_t), &newArp,
                  sizeof (arpMsg_t));

          // Write packet data
          if (fwrite (replyPtr, 1, newPktHdr.incl_len, pcapOutput)
              != newPktHdr.incl_len) // Copy data
            {
              errorExit ("Unsuccessful copy of packet data.");
            }
        }
    }

  else if (htons (frPtr->eth_type) == PROTO_IPv4)
    {
      ipv4Hdr_t *ipHdr = (ipv4Hdr_t *)(frPtr + 1);
      uint8_t *mac;
      if (myIP (ipHdr->ip_dstIP, &mac) && ipHdr->ip_proto == PROTO_ICMP)
        {
          unsigned ipHdrLen = (ipHdr->ip_verHlen & 0x0F) * 4;
          unsigned ipPayLen = htons (ipHdr->ip_totLen) - ipHdrLen;
          void *nextHdr = (void *)((uint8_t *)ipHdr + ipHdrLen);
          icmpHdr_t *icmpHdr = (icmpHdr_t *)nextHdr;

          if (icmpHdr->icmp_type == ICMP_ECHO_REQUEST)
            {
              if (fwrite (pktHdr, 1, sizeof (packetHdr_t), pcapOutput)
                  != sizeof (packetHdr_t)) // Copy Header
                {
                  errorExit ("Unsuccessful copy of packet header.");
                }
              if (fwrite (frPtr, 1, pktHdr->incl_len, pcapOutput)
                  != pktHdr->incl_len) // Copy data
                {
                  errorExit ("Unsuccessful copy of packet data.");
                }

              // Structure to hold packet data
              uint8_t replyFrame[MAXFRAMESZ + 30000];
              memset (replyFrame, 0, MAXFRAMESZ + 30000);
              etherHdr_t *replyPtr = (etherHdr_t *)replyFrame;
              uint8_t offset = 0;

              // Reply packet header
              packetHdr_t newPktHdr;
              newPktHdr.ts_sec = pktHdr->ts_sec;
              newPktHdr.ts_usec = pktHdr->ts_usec + 30;
              newPktHdr.orig_len = pktHdr->orig_len;
              newPktHdr.incl_len = pktHdr->incl_len;

              // Write the header
              if (fwrite (&newPktHdr, 1, sizeof (packetHdr_t), pcapOutput)
                  != sizeof (packetHdr_t))
                {
                  errorExit ("Unsuccessful copy of packet header.");
                }

              // Make the new ethernet header
              etherHdr_t newEthHdr;
              memcpy (newEthHdr.eth_srcMAC, frPtr->eth_dstMAC, ETHERNETHLEN);
              // macToStr(mac, temp); 
              // printf("\n Src MAC: %s\n", temp);
              memcpy (newEthHdr.eth_dstMAC, frPtr->eth_srcMAC, ETHERNETHLEN);
              // macToStr(frPtr->eth_srcMAC, temp); 
              // printf("Dest MAC: %s\n", temp);
              newEthHdr.eth_type = ntohs (PROTO_IPv4);

              // Copy into data blob
              memcpy (replyFrame, &newEthHdr, sizeof (etherHdr_t));
              offset += sizeof (etherHdr_t);

              // Make new IP header
              ipv4Hdr_t newIP;
              newIP.ip_verHlen = ipHdr->ip_verHlen;
              newIP.ip_dscpEcn = ipHdr->ip_dscpEcn;
              newIP.ip_totLen = ipHdr->ip_totLen;
              newIP.ip_id = ntohs (
                  ipID++); // starts at 1000 and increases with each reply
              newIP.ip_flagsFrag = ntohs (0x4000); // do not fragment set
              newIP.ip_ttl = (ipHdr->ip_ttl);
              newIP.ip_proto = ipHdr->ip_proto;
              newIP.ip_hdrChk = 0; // inet_checksum(arg, arg) to calculate this
              newIP.ip_srcIP = ipHdr->ip_dstIP;
              newIP.ip_dstIP = ipHdr->ip_srcIP;


              // ipToStr(newIP.ip_srcIP, temp2); 
              // printf("Src IP: %s\n", temp2); 
              // ipToStr(newIP.ip_dstIP, temp2); 
              // printf("dst IP: %s\n", temp2); 
              

              // Now lets calc the checksum
              newIP.ip_hdrChk = inet_checksum (&newIP, sizeof (ipv4Hdr_t));

              // Copy into data blob
              memcpy (replyFrame + offset, &newIP, sizeof (ipv4Hdr_t));
              offset += sizeof (ipv4Hdr_t);

              // Make ICMP reply message
              icmpHdr_t newICMP;
              newICMP.icmp_type = ICMP_ECHO_REPLY;
              newICMP.icmp_code = 0;
              newICMP.icmp_check = 0;
              memcpy (newICMP.icmp_line2, icmpHdr->icmp_line2, 4);
              memcpy (newICMP.data, icmpHdr->data,
                      ipPayLen - sizeof (icmpHdr_t));

              //cksum
              newICMP.icmp_check = inet_checksum(&newICMP, ipPayLen);

              // Copy into data blob
              memcpy (replyFrame + offset, &newICMP, ipPayLen);

              // Write packet data
              if (fwrite (replyPtr, 1, newPktHdr.incl_len, pcapOutput)
                  != newPktHdr.incl_len) // Copy data
                {
                  errorExit ("Unsuccessful copy of packet data.");
                }
            }
        }
    }
}

/*
Open the output PCAP file ‘fname’ and write its global header
from pre-filled info in buffer 'p'

Returns: 0 on success, -1 on failure
*/
int
writePCAPhdr (char *fname, pcap_hdr_t *p)
{
  pcapOutput = fopen (fname, "w");
  if (pcapOutput == NULL)
    {
      return -1;
    }
  // Do we need to be swapping back the byte order here? it was modified in a
  // previous call to readPCAPHdr if the magic number was off

  if (fwrite (p, 1, sizeof (pcap_hdr_t), pcapOutput) < sizeof (pcap_hdr_t))
    {
      return -1;
    }
  // And then we would need to swap them back here ( ? )
  return 0;
}

/*
Read IP-to-MAC mappings from file 'arpDB' into the global array:
  arpmap_t myARPmap[ MAXARPMAP ] ;

Returns: the actual number of mappings read from the file
  (setting the global 'mapSize' to that same number), or -1 on failure
*/
int
readARPmap (char *arpDB)
{
  FILE *file;
  char buffer[256];
  char *token;
  char *IPtoken;
  int counter = 0;
  unsigned int values[6];
  char IPString[MAXIPv4ADDRLEN];
  char MACBuff[MAXMACADDRLEN];

  file = fopen (arpDB, "r");
  if (file == NULL)
    {
      return -1;
    }

  while (fgets (buffer, sizeof (buffer), file))
    {
      // IP
      token = strtok (buffer, "  ");
      inet_pton (AF_INET, token, &myARPmap[counter].ip);

      // MAC
      token = strtok (NULL, "\n");

      if (!(sscanf (token, "%x:%x:%x:%x:%x:%x", &values[0], &values[1],
                    &values[2], &values[3], &values[4], &values[5])
            == 6))
        {

          return -1;
        }
      for (int i = 0; i < ETHERNETHLEN; i++)
        {
          myARPmap[counter].mac[i] = (uint8_t)values[i];
        }

      inet_ntop (AF_INET, &myARPmap[counter].ip, IPString, MAXIPv4ADDRLEN);

      macToStr (myARPmap[counter].mac, MACBuff);
      printf ("  %d:  %s\t%s\n", counter, IPString, MACBuff);

      // Increment counter
      counter++;
    }

  mapSize = counter;
  // printf("Mapsize: %d\n", mapSize);
  fclose (file);

  return mapSize;
}

/*
Compute and return the Internet Checksum using One-Complement Arithmetic
on an array of 16-bit values pointed to by 'data',
which has a total of ' lenBytes ' bytes (may be an even or odd value)
*/
uint16_t
inet_checksum (void *data, uint16_t lenBytes)
{
  unsigned cksum = 0;
  uint16_t *dataPtr = data;

  for (int i = 0; i < lenBytes / 2; i++)
    {
      cksum += dataPtr[i];
    }

  //If there's an odd number of bytes, add last byte
  if (lenBytes % 2 != 0)
    {
      cksum += ((uint8_t *)data)[lenBytes - 1];
    }

  // Add in the carry bit(s)
  if (cksum > 0xFFFF)
    {
      cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }
  return (~cksum);
}

/*
Check if 'someIP' is one of mine. If not mine, and if ptr is not NULL, then set
*ptr to NULL. If 'someIP' is mine, and if ptr is not NULL , then set *ptr to
point at the corresponding MAC value inside the global 'myARPmap[]' array. Note
that no copying of the actual bytes of the MAC address is done.
*/
bool
myIP (IPv4addr someIP, uint8_t **ptr)
{
  char someIpBuf[MAXIPv4ADDRLEN];
  char mac[MAXMACADDRLEN]; 

  if (ptr == NULL)
    {
      return false;
    }

  for (int i = 0; i < mapSize; i++)
    {
      char IPString[MAXIPv4ADDRLEN];
      ipToStr (someIP, someIpBuf);
      inet_ntop (AF_INET, &myARPmap[i].ip, IPString, MAXIPv4ADDRLEN);

      if (strncmp (IPString, someIpBuf, MAXIPv4ADDRLEN) == 0)
        {
          //macToStr(myARPmap[i].mac, mac); 
          //printf("\n MYIP Function: IP: %s    MAC: %s\n", someIpBuf, mac); 
          *ptr = myARPmap[i].mac;
          return true;
        }
    }
  return false;
}

/*
Check if 'someMAC' is one of mine.
Note that a MAC broadcast address must also be treated as mine
*/
bool
myMAC (uint8_t someMAC[])
{
  char MACBuff[MAXMACADDRLEN];

  for (int i = 0; i < mapSize; i++)
    {
      macToStr (myARPmap[i].mac, MACBuff);
      // printf(" \nTest: \n%s \t %s", someMAC, MACBuff);
      if ((strncmp (someMAC, MACBuff, MAXMACADDRLEN) == 0)
          || (strncmp ("ff:ff:ff:ff:ff:ff", someMAC, MAXMACADDRLEN) == 0))
        {
          return true;
        }
      memset (MACBuff, 0, MAXMACADDRLEN);
    }
  return false;
}

/*-------------------------------------------------------------------------*/
/* Suggested Utility Functions */
/*-------------------------------------------------------------------------*/
/* Convert IPv4 address 'ip' into a dotted-decimal string in 'ipBuf'.
Returns 'ipBuf' */
char *
ipToStr (const IPv4addr ip, char *ipBuf)
{
  // Missing Code Here
  memset (ipBuf, 0, MAXIPv4ADDRLEN);
  snprintf (ipBuf, MAXIPv4ADDRLEN, "%d.%d.%d.%d", ip.byte[0], ip.byte[1],
            ip.byte[2], ip.byte[3]);
  return ipBuf;
}

/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *
macToStr (const uint8_t *p, char *buf)
{
  // Missing Code Here
  memset (buf, 0, strlen (buf));
  snprintf (buf, MAXMACADDRLEN, "%02x:%02x:%02x:%02x:%02x:%02x", *p, *(p + 1),
            *(p + 2), *(p + 3), *(p + 4), *(p + 5));
  return buf;
}
