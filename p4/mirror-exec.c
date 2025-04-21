/*********************************************************************
    PA-04:  Sockets

    FILE:   mirror-exec.c   SKELETON

    Written By: 
		1- Write Student Name Here	
		 
    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include    "myNetLib.h"

void reaper(int sig) ;      // Handle SIGCHLD
void killHandler(int sig) ; // Handle SIGTERM

//------------------------------------------------------------
int main( int argc , char *argv[] )
{
    int     sd_listen ,             // Receiving Socket descriptor to Server
            sd_audit ;              // Socket descriptor with Auditor
    int     queLen = 10 ;           // Max #of pending connection requests
    struct sockaddr_in  cl_addr;    // the address of a client

    char *developerName = "MUST WRITE YOUR NAMES HERE (OR LOSE big POINTS)" ;
    
    printf( "\n****  Mirror Server **** by %s\n\n" , developerName ) ;


    char *auditorIP = AUDITOR_IP ;      // Default Auditor Server

    // Get the optional Auditon IP address from argv, otherwise use default
    switch ( argc )
    {
        
        // .....

    }

    printf("Working with these arguments:\n" ) ;
    printf("\tAuditor Server IP is '%s'\n" , auditorIP ) ;


    // Create a TCP socket bound to this local port MIRROR_TCP_PORT
    sd_listen = socketTCP( /* .... */ ) ;

    // Now, start listening on this TCP port


    printf( "Mirror Server Started. Listening at socket %hu\n" , sd_listen );


    { 
        // This block to be implemented in Phase Two
    
        // Create a UDP socket with ephemeral port, but 'connected' to the Auditor server
        sd_audit = socketUDP( /*  ....  */ ) ;
    
    }

    /* Let reaper clean up after completed child processes */
    sigactionWrapper( .... ) ;
    
    /* Let killHandler() handle CTRL-C or a KILL command from terminal*/
    sigactionWrapper( .... ) ;

   
    // For ever, wait till clients connect to me
    // Will only terminate when I receive a 'SIGTERM'
    while(1)
    {
        // Wait for a client to connect & record the 'accepted' socket in sd_clnt


        // Display IP : Port of the client


        // Delegate a sub-server child process to handle this client
        // Start a subMirror server using one of the 'exec' family of system calls
        // Pass the 'sd_clnt'  and  'sd_audit' to that subServer
        
        // As for the parent server, make sure you close sockets you don't need


    }    

    return 0;
    
}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
 
void reaper(int sig)
{
    pid_t  pid ;
	int	   status;

	// Don't know how many signals, so loop till there are still 
    // more signals from child processes

    while ( ....  ) 
	    fprintf( stderr , "\nA Child server process %d has terminated\n" , pid );

    return ;
}

/*------------------------------------------------------------------------
 * killHandler - clean up after receiving a KILL signal
 *------------------------------------------------------------------------
 */
void killHandler(int sig)
{
    fprintf( stderr , "\nThe Mirror Server is now closing\n" );
    exit(0) ;
}
