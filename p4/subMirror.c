/*********************************************************************
    PA-04:  Sockets

    FILE:   subMirror.c   SKELETON

    Written By:
                1- Abigail Ensogna and Elvis Masinovic

    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include "myNetLib.h"
#define MAXSTRLEN 256
#define CHUNK_SZ 1000

/*------------------------------------------------------------------------
 * This is a child server attending to an incoming client on 'sd'
 * Audit activities to the Auditor via 'sd_audit'
 *------------------------------------------------------------------------
 */

int
main (int argc, char *argv[])
{
  int sd, sd_audit;
  char ipStr[MAXSTRLEN];
  char chunk[CHUNK_SZ];

  int alen;
  struct sockaddr_in clntaddr;

  char *developerName = "Abigail Ensogna and Elvis Masinovic";

  printf ("\n****  sub-Mirror Server **** by %s\n\n", developerName);

  // Get the required  socket descriptors of the Client
  // and of the Auditor from the command line arguments
  sd = atoi (argv[1]);       // client connected TCP socket
  sd_audit = atoi (argv[2]); // Auditor UDP socket

  // what is the difference between what the top is supposed to
  // do vs what this block below is supposed to do
  // This block to be implemented in Phase Two

  audit_t activity;          // activity auditing
  sd_audit = atoi (argv[2]); // Auditor UDP socket

  // find out my IP:Port of the client from
  // the provided socket descriptors
  alen = sizeof (clntaddr);

  if (getsockname (sd, (SA *)&clntaddr, &alen) < 0)
    err_quit ("getsockname error");

  if (!inet_ntop (AF_INET, &clntaddr.sin_addr, ipStr, MAXSTRLEN))
    err_quit ("inet_ntop error");

  while (1) // Loop until client closes socket
    {
      // Get a chunk of data from the client. Wisely choose which
      // variant of the read() wrappers to use here
      ssize_t numRead = Read (sd, chunk, CHUNK_SZ);

      // This block to be implemented in Phase Two

      // Report this receive activity to the Auditor
      activity.op = 2;
      activity.nBytes = numRead;
      activity.ip = clntaddr.sin_addr.s_addr;
      // sendto(....)

      // send all bytes received above back to the client
      write (sd, chunk, numRead);

      // This block to be implemented in Phase Two

      // Report this send activity to the Auditor
      activity.op = 1;
      activity.nBytes = numRead;
      activity.ip = clntaddr.sin_addr.s_addr;
      //sendto(....);

      memset (chunk, 0, CHUNK_SZ);
    }

  Close (sd);
}
