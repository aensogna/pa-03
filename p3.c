
/* ------------------------------------------------------------------------
CS-455 Advanced Computer Networking
Simplified Packet Analysis Programming Projects
Designed By: Dr. Mohamed Aboutabl (c) 2020, 2025
Implemented By: Abigail Ensogna
File Name: p1.c
---------------------------------------------------------------------------*/
#include "mypcap.h"
/*-------------------------------------------------------------------------*/
void
usage (char *cmd)
{
  printf ("Usage: %s input PCAP (.pcap), output PCAP name (.pcap), ARP Pairs (.dat)\n", cmd);
}
/*-------------------------------------------------------------------------*/
int
main (int argc, char *argv[])
{
  char *pcapIn;
  char *pcapOut;
  char *arpData; 
  pcap_hdr_t pcapHdr;
  packetHdr_t pktHdr;
  uint8_t ethFrame[MAXFRAMESZ + 30000];
  etherHdr_t *frameHdrPtr = (etherHdr_t *)ethFrame;
  if (argc < 3)
    {
      usage (argv[0]);
      exit (EXIT_FAILURE);
    }
  
  // Input files
  pcapIn = argv[1];
  pcapOut = argv[2]; 
  arpData = argv[3]; 

  printf ("\nProcessing PCAP file '%s'\n\n", pcapIn);
  // Read the global header of the pcapInput file
  // By calling readPCAPhdr().
  // If error occured, call errorExit("Failed to read global header from the
  // PCAP file " )
  int readStat = readPCAPhdr (pcapIn, &pcapHdr);
  if (readStat == -1)
    {
      errorExit ("Failed to read global header from the PCAP file");
    }
  // Print the global header of the pcap filer
  printPCAPhdr(&pcapHdr);
  // Print labels before any packets are printed
  puts ("");
  printf ("%6s %14s %11s %-20s %-20s %8s %s\n", "PktNum", "Time Stamp",
          "OrgLen / Captrd", "Source", "Destination", "Protocol", "info");
  uint32_t serialNo = 1;
  // Read one packet at a time
  while (getNextPacket(&pktHdr, ethFrame))
    {
      printf ("%6u ", serialNo++);
      // Use packetMetaDataPrint() to print the packet header data;
      // Time is printed relative to the 1st packet's time
      // Use packetPrint( ) to print the actual content of the packet starting
      // at the ethernet level and up
      printPacketMetaData(&pktHdr);
      printPacket(frameHdrPtr);
      puts ("");
      memset(ethFrame, 0, MAXFRAMESZ);
    }
  printf ("\nReached end of PCAP file '%s'\n", pcapIn);
  cleanUp ();
}
