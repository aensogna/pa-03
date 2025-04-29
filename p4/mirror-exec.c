/*********************************************************************
    PA-04:  Sockets

    FILE:   mirror-exec.c   SKELETON

    Written By:
                Abigail Ensogna and Elvis Masinovic

    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include "myNetLib.h"

#define SIGCHILD_NO 17
#define SIGKILL_NO 9

void reaper (int sig);      // Handle SIGCHLD
void killHandler (int sig); // Handle SIGTERM

//------------------------------------------------------------
int
main (int argc, char *argv[])
{
  int sd_listen,              // Receiving Socket descriptor to Server
      sd_audit;               // Socket descriptor with Auditor
  int queLen = 10;            // Max #of pending connection requests
  struct sockaddr_in cl_addr; // the address of a client

  char *developerName = "Abigail Ensogna and Elvis Masinovic";

  printf ("\n****  Mirror Server **** by %s\n\n", developerName);

  char *auditorIP = AUDITOR_IP; // Default Auditor Server

  // Get the optional Auditon IP address from argv, otherwise use default
  switch (argc)
    {
    case 2:
      auditorIP = argv[2];

    case 1:

    default:
      break;
    }

  printf ("Working with these arguments:\n");
  printf ("\tAuditor Server IP is '%s'\n", auditorIP);

  // Create a TCP socket bound to this local port MIRROR_TCP_PORT
  sd_listen = socketTCP (MIRROR_TCP_PORT, NULL, 0);

  // Now, start listening on this TCP port
  Listen (sd_listen, queLen);

  printf ("Mirror Server Started. Listening at socket %hu\n", sd_listen);

  {
    // This block to be implemented in Phase Two

    // Create a UDP socket with ephemeral port, but 'connected' to the Auditor
    // server
    //sd_audit = socketUDP (/*  ....  */);
  }

  /* Let reaper clean up after completed child processes */
  sigactionWrapper (SIGCHILD_NO, &reaper);

  /* Let killHandler() handle CTRL-C or a KILL command from terminal*/
  sigactionWrapper (SIGKILL_NO, &killHandler);

  // For ever, wait till clients connect to me
  // Will only terminate when I receive a 'SIGTERM'
  while (1)
    {
      unsigned int clAddrLen = sizeof (cl_addr);
      int sd_clnt;

      // Wait for a client to connect & record the 'accepted' socket in sd_clnt
      sd_clnt = Accept (sd_listen, (struct sockaddr *)&cl_addr, (socklen_t *)&clAddrLen);

      struct sockaddr_in clientSocket;
      unsigned int cliSockLen = sizeof(clientSocket);
      char ipStr[20];

      if (getpeername (sd_clnt, (struct sockaddr *)&clientSocket, (socklen_t *)&cliSockLen) != 0)
        {
          err_quit ("getpeername error");
        }

      if (inet_ntop (AF_INET, (void *)&clientSocket.sin_addr, ipStr,
                     sizeof (clientSocket)) == NULL)
        {
          err_quit ("inet ntop error");
        }

      // Display IP : Port of the client
      printf ("%s : %hu\n", ipStr, ntohs(clientSocket.sin_port));

      // Delegate a sub-server child process to handle this client
      // Start a subMirror server using one of the 'exec' family of system
      pid_t pid = Fork();
      char sd_clnt_str[50];
      memset(sd_clnt_str, 0 , sizeof(sd_clnt_str));
      char sd_audit_str[50];
      memset(sd_audit_str, 0 , sizeof(sd_audit_str));
      execl("subMirror", sd_clnt_str, sd_audit_str, NULL);
      // calls Pass the 'sd_clnt'  and  'sd_audit' to that subServer

      // As for the parent server, make sure you close sockets you don't need
      Close(sd_clnt);
    }

  return 0;
}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */

void
reaper (int sig)
{
  pid_t pid;
  int status;

  // Don't know how many signals, so loop till there are still
  // more signals from child processes

  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    fprintf (stderr, "\nA Child server process %d has terminated\n", pid);

  return;
}

/*------------------------------------------------------------------------
 * killHandler - clean up after receiving a KILL signal
 *------------------------------------------------------------------------
 */
void
killHandler (int sig)
{
  fprintf (stderr, "\nThe Mirror Server is now closing\n");
  exit (0);
}
