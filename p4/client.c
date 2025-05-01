/*********************************************************************
    PA-04:  Sockets

    FILE:   client.c   SKELETON

    Written By:
                1- Abigail Ensogna and Elvis Masinovic

    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include "myNetLib.h"

void mirrorFile (int in, int copy, int mirror, int audit);

int
main (int argc, char *argv[])
{
  int sd_mirror,   // Socket to Mirror TCP server
      sd_audit;    // Socket to Auditor UDP server
  int queLen = 10; // Max #of pending connection requests

  char *mirrorIP = MIRROR_IP,                 // default Mirror Server
      *auditorIP = AUDITOR_IP,                // Default Auditor Server
          *inFile = "GoldilockAnd3Bears.txt"; // Default input file

  printf ("\nClient by Abigail Ensogna and Elvis Masinovic has Started\n");

  // Get the command-line arguments

  switch (argc)
    {
    case 4:
      auditorIP = argv[3];
    case 3:
      mirrorIP = argv[2];
    case 2:
      inFile = argv[1];
    case 1:
      break;

    default:
      printf ("\nInvalid argument(s). Usage: %s <inputFileName> [mirror-IP]"
              " [auditor-IP]\n\n",
              argv[0]);
      exit (-1);
    }

  printf ("Working with these arguments:\n");
  printf ("\tInput   File Name is '%s'\n", inFile);
  printf ("\tMirror  Server IP is '%s'\n", mirrorIP);
  printf ("\tAuditor Server IP is '%s'\n", auditorIP);

  int fd_in, fd_cpy;

  // Open the input file and create the copy file by same name.copy
  fd_in = open (inFile, O_RDONLY);
  //printf("in file: %d\n", fd_in);
  char cpy_name[50];
  snprintf(cpy_name, sizeof(cpy_name), "%s.copy", inFile);
  //printf("%s\n", cpy_name);
  fd_cpy = open (cpy_name, O_CREAT | O_WRONLY | O_TRUNC, 0777);
  //printf("fd cp %d", fd_cpy);

  // Use sockettCP() to create a local TCP socket with ephemeral port, and
  // connect it to the mirror server at  mirrorIP : MIRROR_TCP_PORT

  puts ("");
  sd_mirror = socketTCP (0, MIRROR_IP, MIRROR_TCP_PORT); // second Arg?
  printf ("TCP Client is now connected to the TCP Mirror server %s : %hu\n",
          MIRROR_IP, MIRROR_TCP_PORT);

  
    // This block to be implemented in Phase Two

    // Use socketUDP to created an ephemeral local UDP socket and restrict
    // its peer to the Auditor server
  sd_audit = socketUDP (0, AUDITOR_IP, AUDITOR_UDP_PORT);
  

  // Now, Start moving data: fd_in ==> sd_mirror ==> fd_cpy
  // While logging all send and receive transactions to
  // the Auditor UDP Server
  mirrorFile (fd_in, sd_mirror, fd_cpy, sd_audit);

  puts ("TCP Client finished sending the local file to the TCP Mirror server");
  //Close( sd_mirror ) ;  // Observe the traffic when we use close() vs
  // shutdown()
  shutdown (sd_mirror, SHUT_WR);
  puts ("\nTCP Client closed the connection to the TCP Mirror server\n");

  return 0;
}

/*------------------------------------------------------------------------
 * Trasfer data from descriptor 'in' to descriptor 'mirror'
 * and receive it back through descriptor 'mirror'.
 * // This is for Phase Two: Report sending & receiving transactions to
 *descriptor 'audit'
 *------------------------------------------------------------------------*/

#define CHUNK_SZ 1000
#define MAXSTRLEN 256

void
mirrorFile (int in, int mirror, int copy, int audit)
{
  unsigned char buf[CHUNK_SZ], buf2[CHUNK_SZ], mirrorStr[MAXSTRLEN],
      myStr[MAXSTRLEN];
  audit_t activity; // This is for Phase Two
  struct sockaddr_in mySocket, mirrorServer;
  int alen;

  // Learn my IP:Port associated with 'mirror'
  alen = sizeof (mirrorServer);
  if (getsockname (mirror, (SA *)&mirrorServer, &alen) < 0)
    {
      err_quit ("getsockname err");
    }

  if (!inet_ntop (AF_INET, &mirrorServer.sin_addr, mirrorStr, MAXSTRLEN))
    {
      err_quit ("inet_ntop err");
    }

  // Do we need to be printing here
  memset (myStr, 0, MAXSTRLEN);

  // Learn the IP:Port of my peer on the other side of 'mirror'
  if (getpeername (mirror, (SA *)&mySocket, &alen) < 0)
    {
      err_quit ("getpeername err");
    }

  if (!inet_ntop (AF_INET, (void *)&mySocket.sin_addr, myStr, MAXSTRLEN))
    {
      err_quit ("inet ntop peer error");
    }

  // Repeat untill all data has been sent and received back
  // As this happens, save the received copy to the 'copy' file descriptor
  while (1)
    {
      // Get up to CHUNK_SZ bytes from input file  and send ALL of what I get
      // to the 'mirror' socket
      ssize_t numRead = Read (in, buf, CHUNK_SZ);
      if (numRead == 0){
        break; 
      }
      ssize_t numWrite = writen (mirror, buf, numRead);
      // This block to be implemented in Phase Two

      // by setting the fields of 'activity'
      // Report this sending activity to the Auditor
      activity.op = 1;
      activity.nBytes = numRead;
      activity.ip = mySocket.sin_addr.s_addr;

      writen(audit, &activity, sizeof(activity)); 

      // Now read from 'mirror' EXACTLY the same number of bytes I sent earlier
      Readn (mirror, buf2, numRead);
      // This block to be implemented in Phase Two

      // Report this receiving activity to the Auditor
      // by setting the fields of 'activity'
      activity.op = 2;
      activity.nBytes = numRead;
      activity.ip = mySocket.sin_addr.s_addr;
      writen(audit, &activity, sizeof(activity)); 
      // Finally, save a copy of what I received back to the 'copy' file
      writen (copy, buf2, numRead);

      memset (buf, 0, CHUNK_SZ);
      memset (buf2, 0, CHUNK_SZ);
    }
}
