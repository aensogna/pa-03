/*********************************************************************
    PA-04:  Sockets

    FILE:   subMirror.c   SKELETON 

    Written By: 
		1- Write Student Name Here	
		 
    Submitted on:   <PUT DATE  HERE >
**********************************************************************/

#include    "myNetLib.h"

/*------------------------------------------------------------------------
 * This is a child server attending to an incoming client on 'sd'
 * Audit activities to the Auditor via 'sd_audit'
 *------------------------------------------------------------------------
 */


int main( int argc , char *argv[] )
{
    int sd, sd_audit ;
    
    char *developerName = "Abigail Ensogna and Elvis Masinovic" ;
    
    printf( "\n****  sub-Mirror Server **** by %s\n\n" , developerName ) ;

        
    // Get the required  socket descriptors of the Client
    // and of the Auditor from the command line arguments

    sd        = /* .... */ ;  // client connected TCP socket
    sd_audit  = /* .... */ ;  // Auditor UDP socket

    { 
        // This block to be implemented in Phase Two
    
        audit_t  activity ;     // activity auditing
        sd_audit  = atoi( argv[2] ) ;  // Auditor UDP socket
    }

    
    // find out my IP:Port of the client from 
    // the provided socket descriptors
        

      
    while ( 1 )   // Loop until client closes socket
    {
        // Get a chunk of data from the client. Wisely choose which 
        // variant of the read() wrappers to use here


        { 
            // This block to be implemented in Phase Two
        
            // Report this receive activity to the Auditor
        }
        

        // send all bytes received above back to the client


        { 
            // This block to be implemented in Phase Two
        
            // Report this send activity to the Auditor
        }
    }

    Close ( sd ) ;
}
