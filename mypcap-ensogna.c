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
  ipPayLen = htons(q->ip_totLen) - ipHdrLen;

  optLen = ipHdrLen - sizeof (ipv4Hdr_t); // The minimup IP header is 20 bytes
  nextHdr = (void *)((uint8_t *)q + ipHdrLen);

  // Calculate the IP header options length in bytes
  switch (q->ip_proto)
    {
    case PROTO_ICMP:
      printf ("%-8s ", "ICMP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned icmpHdrLen = printICMPinfo((icmpHdr_t *)nextHdr);
      dataLen = ipPayLen - icmpHdrLen;
      // Print the details of the ICMP message by calling printICMPinfo()
      // Compute 'dataLen' : the length of the data section inside the ICMP
      // message
      break;
    case PROTO_TCP:
      printf ("%-8s ", "TCP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned tcpHdrLen = printTCPinfo((tcpHdr_t *)nextHdr);
      dataLen = ipPayLen - tcpHdrLen;
      // Leave dataLen as Zero for now
      break;
    case PROTO_UDP:
      printf ("%-8s ", "UDP");
      // Print IP header length and numBytes of the options
      printf ("IP_HDR{ Len=%d incl. %d options bytes}", ipHdrLen, optLen);
      unsigned udpHdrLen = printUDPinfo((udpHdr_t *)nextHdr);
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
          printf ("Echo Reply   :id=%5d, seq=%5d", htons(*id), htons(*seqNum));
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
          printf ("Echo Request :id=%5d, seq=%5d", htons(*id), htons(*seqNum));
        }
      else
        {
          printf ("Echo Request : %19s %3d", "INVALID Code:", p->icmp_code);
        }
      break;
    default:
      printf ("Type %3d , code %3d Not Yet Supported", p->icmp_type, p->icmp_code);
    }
  printf ("}");
  return icmpHdrLen;
}

/*  Project 2  */
unsigned printTCPinfo( const tcpHdr_t *p )
{
  const char *protocol = "tcp";
  unsigned tcpHdrLen = sizeof(tcpHdr_t);
  struct servent *srcServ, *dstServ;
  char *srcName, *dstName;
  char *ackStr, *pshStr, *rstStr, *synStr, *finStr;
  unsigned hlen, optLen, src, dst, seqNum, ackNum, rwnd;
  bool ack, psh, rst, syn, fin;

  src = htons(p->tcp_srcPort);
  dst = htons(p->tcp_dstPort);
  seqNum = htonl(p->tcp_seqNum);
  ackNum = htonl(p->tcp_ackNum);
  rwnd = htons(p->tcp_window);

  ack = (htons(p->tcp_hlen_reserved_flags) & (1 << 4));
  if (ack) {ackStr = "ACK ";} else {ackStr = "    ";}
  psh = (htons(p->tcp_hlen_reserved_flags) & (1 << 3));
  if (psh) {pshStr = "PSH ";} else {pshStr = "    ";}
  rst = (htons(p->tcp_hlen_reserved_flags) & (1 << 2));
  if (rst) {rstStr = "RST ";} else {rstStr = "    ";}
  syn = (htons(p->tcp_hlen_reserved_flags) & (1 << 1));
  if (syn) {synStr = "SYN ";} else {synStr = "    ";}
  fin = (htons(p->tcp_hlen_reserved_flags) & 1);
  if (fin) {finStr = "FIN ";} else {finStr = "    ";}

  hlen = ((htons(p->tcp_hlen_reserved_flags) & 0xF000) * 4) >> 12;
  optLen = hlen - sizeof(tcpHdr_t);

  printf(" TCPhdr=%2u (Options %2u bytes) ", hlen, optLen);

  srcServ = getservbyport(ntohs(src), protocol);
  if (srcServ) { srcName = srcServ->s_name; } else { srcName = "*** "; }
  printf("Port %5u (%7s) -> ", src, srcName);

  dstServ = getservbyport(ntohs(dst), protocol);
  if (dstServ) { dstName = dstServ->s_name; } else { dstName = "*** "; }
  printf("%5u (%7s) ", dst, dstName);

  printf("[%s%s%s%s%s] Seq=%10u ", synStr, pshStr, ackStr, finStr, rstStr, seqNum);
  
  if (ackNum) { printf("Ack=%10u ", ackNum); } else  {printf("               "); }
  
  printf("Rwnd=%5hu", rwnd);

  return tcpHdrLen + optLen;
}

unsigned printUDPinfo( const udpHdr_t *p )
{
  unsigned udpHdrLen = sizeof(udpHdr_t);
  struct servent *srcServ, *dstServ;
  unsigned src, dst, len, cksum;
  const char *protocol = "udp";
  char *srcName, *dstName;

  src = htons(p->udp_srcPort);
  dst = htons(p->udp_dstPort);
  len = htons(p->udp_len);
  cksum = htons(p->udp_cksum);

  printf(" UDP %5u Bytes. ", len);

  srcServ = getservbyport(htons(src), protocol);
  if (srcServ) { srcName = srcServ->s_name; } else { srcName = "*** "; }

  printf("Port %5u (%7s) -> ", src, srcName);

  dstServ = getservbyport(htons(dst), protocol);
  if (dstServ) { dstName = dstServ->s_name; } else { dstName = "*** "; }

  printf("%5u (%7s) ", dst, dstName);
  return udpHdrLen;
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

