/*********************************************************************
    PA-04:  Sockets

    FILE:   client.c   SKELETON

    Written By: 
		1- Write Student Name Here	
		 
    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include    "myNetLib.h"

void mirrorFile( int in , int copy , int mirror , int audit );

int main( int argc , char *argv[] )
{
    int     sd_mirror ,     // Socket to Mirror TCP server
            sd_audit  ;     // Socket to Auditor UDP server
    int     queLen = 10 ;   // Max #of pending connection requests

    char *mirrorIP  = MIRROR_IP ,                   // default Mirror Server
         *auditorIP = AUDITOR_IP ,                  // Default Auditor Server
         *inFile    = "GoldilockAnd3Bears.txt" ;    // Default input file

    printf( "\nClient by <YOUR_FULL_NAMES> has Started\n" );

    // Get the command-line arguments

    switch ( argc )
    {
        case 4: auditorIP = argv[3] ;
        case 3: mirrorIP  = argv[2] ;
        case 2: inFile    = argv[1] ;
        case 1: break ;

        default:
            printf("\nInvalid argument(s). Usage: %s <inputFileName> [mirror-IP]"
            " [auditor-IP]\n\n" , argv[0] ) ;
            exit(-1);        
    }

    printf("Working with these arguments:\n" ) ;
    printf("\tInput   File Name is '%s'\n" , inFile    ) ;
    printf("\tMirror  Server IP is '%s'\n" , mirrorIP  ) ;
    printf("\tAuditor Server IP is '%s'\n" , auditorIP ) ;

    int  fd_in , fd_cpy ;

    // Open the input file and create the copy file by same name.copy

    // Use sockettCP() to create a local TCP socket with ephemeral port, and connect it to
    // the mirror server at  mirrorIP : MIRROR_TCP_PORT

    puts("") ;
    sd_mirror = socketTCP( /* ... */  );
    printf("TCP Client is now connected to the TCP Mirror server %s : %hu\n" , 
            ..... ) ;

    { 
        // This block to be implemented in Phase Two
    
        // Use socketUDP to created an ephemeral local UDP socket and restrict 
        // its peer to the Auditor server
        sd_audit = socketUDP( /* .... */ ) ;
    
    }

    // Now, Start moving data: fd_in ==> sd_mirror ==> fd_cpy
    // While logging all send and receive transactions to
    // the Auditor UDP Server
    mirrorFile( fd_in , sd_mirror , fd_cpy  , sd_audit  ) ;
    
    puts("TCP Client finished sending the local file to the TCP Mirror server");
    // Close( sd_mirror ) ;  // Observe the traffic when we use close() vs shutdown()
    shutdown( sd_mirror , SHUT_WR ) ;
    puts("\nTCP Client closed the connection to the TCP Mirror server\n");
    
    return 0;
    
}

/*------------------------------------------------------------------------
 * Trasfer data from descriptor 'in' to descriptor 'mirror' 
 * and receive it back through descriptor 'mirror'. 
 * // This is for Phase Two: Report sending & receiving transactions to descriptor 'audit'
 *------------------------------------------------------------------------*/
 
#define CHUNK_SZ  1000
#define MAXSTRLEN 256

void mirrorFile( int in , int mirror , int copy , int audit )
{
    unsigned char buf[ CHUNK_SZ ] , buf2[ CHUNK_SZ ]  , str[MAXSTRLEN];
    audit_t  activity ; // This is for Phase Two
    struct sockaddr_in      mySocket, mirrorServer ;
    int    alen ;
    
    // Learn my IP:Port associated with 'mirror' 
        
    // Learn the IP:Port of my peer on the other side of 'mirror'     
        
    // Repeat untill all data has been sent and received back
    // As this happens, save the received copy to the 'copy' file descriptor
    while ( 1 )
    {
        // Get up to CHUNK_SZ bytes from input file  and send ALL of what I get
        // to the 'mirror' socket


        { 
            // This block to be implemented in Phase Two

            // by setting the fields of 'activity'        
            // Report this sending activity to the Auditor
        
        }
       
        // Now read from 'mirror' EXACTLY the same number of bytes I sent earlier

        { 
            // This block to be implemented in Phase Two
        
            // Report this receiving activity to the Auditor
            // by setting the fields of 'activity'
        
        }
        
        // Finally, save a copy of what I received back to the 'copy' file
        
    }
    
}
