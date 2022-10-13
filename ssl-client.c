/******************************************************************************

PROGRAM:  ssl-client.c
AUTHOR:   ***** Lincoln Lorscheider, Kaycee Valdez, Bryant Hanks *****
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small client application that establishes a secure
          TCP connection to a server and simply exchanges messages. It uses a
          SSL/TLS connection using X509 certificates generated with the ssl
          application.

          Some of the code and descriptions can be found in "Network Security
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>
#define DEFAULT_PORT        4433
#define BACKUP_PORT         4434
#define DEFAULT_HOST        "localhost"
#define BACKUP_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         256
#define MAX_FILENAME_LENGTH 250

//Declare function prototypes
int download_file(SSL *ssl, const char* filename);
int listFiles(SSL *ssl);
bool checkPassword (const char* password);// See answer @ https://stackoverflow.com/questions/10273414/library-for-passwords-salt-hash-in-c
void setActiveServer(int* port,  const char* host); //This method should be called on pointers to int and char array, so that we can pass those variables into create_socket()
/******************************************************************************

This function does the basic necessary housekeeping to establish a secure TCP
connection to the server specified by 'hostname'.

*******************************************************************************/
int create_socket(char* hostname, unsigned int port) {
  int                sockfd;
  struct hostent*    host;
  struct sockaddr_in dest_addr;

  host = gethostbyname(hostname);
  if (host == NULL) {
    fprintf(stderr, "Client: Cannot resolve hostname %s\n",  hostname);
    exit(EXIT_FAILURE);
  }

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. The s_addr field is the network address of the remote host
  // specified on the command line. The earlier call to gethostbyname()
  // retrieves the IP address for the given hostname.
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  // Now we connect to the remote host.  We pass the connect() system call the
  // socket descriptor, the address of the remote host, and the size in bytes
  // of the remote host's address
  if (connect(sockfd, (struct sockaddr *) &dest_addr,
	      sizeof(struct sockaddr)) <0) {
    fprintf(stderr, "Client: Cannot connect to host %s [%s] on port %d: %s\n",
	    hostname, inet_ntoa(dest_addr.sin_addr), port, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

/******************************************************************************

The sequence of steps required to establish a secure SSL/TLS connection is:

1.  Initialize the SSL algorithms
2.  Create and configure an SSL context object
3.  Create an SSL session object
4.  Create a new network socket in the traditional way
5.  Bind the SSL object to the network socket descriptor
6.  Establish an SSL session on top of the network connection

Once these steps are completed successfully, use the functions SSL_read() and
SSL_write() to read from/write to the socket, but using the SSL object rather
then the socket descriptor.  Once the session is complete, free the memory
allocated to the SSL object and close the socket descriptor.

******************************************************************************/
int main(int argc, char** argv) {
  const SSL_METHOD* method;
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              buffer[BUFFER_SIZE];
  char*             temp_ptr;
  int               sockfd;
  int               writefd;
  int               rcount;
  int               wcount;
  int               total = 0;
  SSL_CTX*          ssl_ctx;
  SSL*              ssl;

  // *******************   this section might need to go away. From here... ******************
  if (argc != 2) {
    fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
    exit(EXIT_FAILURE);
  } else {
    // Search for ':' in the argument to see if port is specified
    temp_ptr = strchr(argv[1], ':');
    if (temp_ptr == NULL)    // Hostname only. Use default port
      strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
    else {
      // Argument is formatted as <hostname>:<port>. Need to separate
      // First, split out the hostname from port, delineated with a colon
      // remote_host will have the <hostname> substring
      strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
      // Port number will be the substring after the ':'. At this point
      // temp is a pointer to the array element containing the ':'
      port = (unsigned int) atoi(temp_ptr+sizeof(char));
    }
  }
    // ******************************* ...down to here ***********************************
  // Initialize OpenSSL ciphers and digests
  OpenSSL_add_all_algorithms();

  // SSL_library_init() registers the available SSL/TLS ciphers and digests.
  if(SSL_library_init() < 0) {
    fprintf(stderr, "Client: Could not initialize the OpenSSL library!\n");
    exit(EXIT_FAILURE);
  }

  // Use the SSL/TLS method for clients
  method = SSLv23_client_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Unable to create a new SSL context structure.\n");
    exit(EXIT_FAILURE);
  }

  // This disables SSLv2, which means only SSLv3 and TLSv1 are available
  // to be negotiated between client and server
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
  // Create a new SSL connection state object
  ssl = SSL_new(ssl_ctx);
  // **** Bryant should insert his checkPassword() call here, maybe inside a while loop until it's auth'd ***
  // **** kaycee should insert her setActiveServer call here ***
  setActiveServer(remote_host,port)
  // Create the underlying TCP socket connection to the remote host
  sockfd = create_socket(remote_host, port);
  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", remote_host, port);
  else {
    fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  // Bind the SSL object to the network socket descriptor. The socket descriptor
  // will be used by OpenSSL to communicate with a server. This function should
  // only be called once the TCP connection is established, i.e., after
  // create_socket()
  SSL_set_fd(ssl, sockfd);

  // Initiates an SSL session over the existing socket connection. SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1)
    printf("Client: Established SSL/TLS session to '%s' on port %u\n", remote_host, port);
  else {
    fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  int status;
  //get filename from user
  printf("Please enter filename to request from server (filename must not have spaces), or type 'ls' to receive a list of available files: ");
  fgets(buffer, BUFFER_SIZE-1, stdin);
  buffer[strlen(buffer)-1] = '\0';
  // **** Bryant Modify this section to either call listFiles() or download_file(), based on if buffer == "ls" or not
  status = download_file(ssl, buffer);
  switch (status){
      case 0:
          printf("%s downloaded\n", buffer);
          break;
          // ******* TODO update ERROR messages **********
      case 1:
          printf("SERVER ERROR: Could not open requested file\n");
          break;
      case 2:
          printf("SERVER ERROR: Opened, but could not read requested file\n");
          break;
      case 3:
          printf("SERVER ERROR: Server could not write to socket during file transmission\n");
          break;
      case 4:
          printf("RPC ERROR, invalid command\n");
          break;
      case 5:
          printf("RPC ERROR, requested path is a directory, not a file\n");
          break;
      case 6:
          printf("RPC ERROR: Too many arguments provided. Ensure no spaces in file name\n");
          break;
      default:
          printf("Undefined Error Code: %d\n", status);
  }

  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  close(sockfd);
  printf("Client: Terminated SSL/TLS connection with server '%s'\n",
	 remote_host);

  return EXIT_SUCCESS;
}

int download_file(SSL *ssl, const char* filename){
    // **** TODO Bryant modify this method as necessary to receive mp3s. The error code mapping in main() will also need to get updated
    int nbytes_written;
    int nbytes_read;
    int file_descriptor;
    int status = 0;
    int error_number;
    char request[BUFFER_SIZE];
    char local_buffer[BUFFER_SIZE];
    bool file_complete = false;

    sprintf(request,"GET: %s", filename); //append user-input filepath to appropriate request type (in order to test RPC format error detection, change to something other than GET and build/run)
    nbytes_written = SSL_write(ssl,request,BUFFER_SIZE);//send request to server
    if (nbytes_written < 0)
        fprintf(stderr, "Client: Error writing to socket: %s\n", strerror(errno));
    else {
        file_descriptor = open(filename, O_CREAT|O_RDWR,(mode_t)0644);
        while (file_complete==false) {
            nbytes_read = SSL_read(ssl, local_buffer, BUFFER_SIZE);
            if (nbytes_read < 0)
                fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
            else if (nbytes_read == 0) {
                printf("Connection Terminated by Server\n");
                file_complete = true;
            }
            else {
                error_number = sscanf(local_buffer, "ERROR: %d", &status);
                if (error_number == 0){
                    write(file_descriptor, local_buffer, BUFFER_SIZE);
                }
                else{
                    file_complete = true;
                }
            }
            bzero(local_buffer, BUFFER_SIZE);
        }
        close(file_descriptor);
    }
    return status;
}

int listFiles(SSL *ssl){
    // **** TODO Bryant modify this method as necessary to print the file list to console. The error code mapping in main() will also need to get updated. It should probably get it's own
    int status = 0;
    int error_number;
    char request[BUFFER_SIZE];
    char local_buffer[BUFFER_SIZE];
    // request = "LIST *.mp3"
}

// Kaycee's code for setActiveServer
void setActiveServer(int* port,  const char* host) {
  int         port = DEFAULT_PORT;
  int*        port_default;
  char        host = DEFAULT_HOST;
  const char* host_default; 

  port_default = &port;
  host_default = &host; 

  // Creates the underlying TCP socket connection to the remote host
  sockfd = create_socket(host_default, port_default);

  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", host_default, port_default);

  // The first attempt to connect did not succeed; tries the backup server
  else {
    port2 = BACKUP_PORT;
    int* port_backup;
    host2 = BACKUP_HOST; 
    const char* host_backup;

    port_backup = &port2;
    host_backup = &host2; 

    printf("Trying backup server on port %u\n", port_backup);
    sockfd = create_socket(host_backup, port_backup);
    if(sockfd != 0)
      fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", host_backup, port_backup);
    else {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", host_backup, port_backup);
      exit(EXIT_FAILURE);
    }
  }
}
