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
#include <time.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>
#include <malloc.h>

#define DEFAULT_PORT        4433
#define BACKUP_PORT         4434
#define DEFAULT_HOST        "localhost"
#define BACKUP_HOST         "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         512
#define MAX_FILENAME_LENGTH 250

//Declare function prototypes
int download_file(SSL *ssl, const char* filename);
char* encrypt(char* input, char output[65]);
bool checkPassword (char* userInput);
int setActiveServer();
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
    sockfd=-1;
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
  int               status;

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
    
    printf("\nPlease enter password:\n");
    fgets(buffer, BUFFER_SIZE-1, stdin);
    buffer[strlen(buffer)-1] = '\0';

    if( !checkPassword(buffer) ){
        printf("\nPassword check has failed!\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    else {
        printf("\nPassword Accepted!\n");

        // This disables SSLv2, which means only SSLv3 and TLSv1 are available
        // to be negotiated between client and server
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
        // Create a new SSL connection state object
        ssl = SSL_new(ssl_ctx);
        // **** kaycee should insert her setActiveServer call here ***

        // Create the underlying TCP socket connection to the remote host
        sockfd = setActiveServer();
        // Bind the SSL object to the network socket descriptor. The socket descriptor
        // will be used by OpenSSL to communicate with a server. This function should
        // only be called once the TCP connection is established, i.e., after
        // create_socket()
        SSL_set_fd(ssl, sockfd);

        // Initiates an SSL session over the existing socket connection. SSL_connect()
        // will return 1 if successful.
        if (SSL_connect(ssl) == 1)
            printf("Client: Established SSL/TLS session to server\n");
        else {
            fprintf(stderr, "Client: Could not establish SSL session to server\n");
            exit(EXIT_FAILURE);
        }
        //get filename from user
        printf("Please enter filename to request from server (filename must not have spaces),\n or type 'ls' to receive a list of available files: ");
        fgets(buffer, BUFFER_SIZE - 1, stdin);
        buffer[strlen(buffer) - 1] = '\0';
        status = download_file(ssl, buffer);
        switch (status) {
            case 0:
                printf("%s downloaded\n", buffer);
                break;
            case 1:
                printf("SERVER ERROR: Could not open requested file\n");
                break;
            case 2:
                printf("SERVER ERROR: Opened, but could not read requested file\n");
                break;
            case 3:
                printf("CLIENT ERROR: Server could not write to socket during file transmission\n");
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
            case 7:
                printf("CLIENT ERROR: Could not read from socket\n");
                break;
            case 10:
                printf("SERVER ERROR: Could not open MP3 directory\n");
                break;
            default:
                printf("Undefined Error Code: %d\n", status);
                break;
        }

        // Deallocate memory for the SSL data structures and close the socket
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        printf("Client: Terminated SSL/TLS connection with server\n");
    }
    return EXIT_SUCCESS;
}

int download_file(SSL *ssl, const char* filename){
    int nbytes_written;
    int nbytes_read;
    int file_descriptor;
    int error_number = 0;
    int filedata_size = 257;
    int operation_size;
    char request[BUFFER_SIZE];
    char local_buffer[BUFFER_SIZE];
    bool transfer_complete = false;

    sprintf(request,"GET: %s", filename); //append user-input filepath to appropriate request type (in order to test RPC format error detection, change to something other than GET and build/run)
    nbytes_written = SSL_write(ssl,request,BUFFER_SIZE);//send request to server
    if (nbytes_written < 0){
        fprintf(stderr, "Client: Error writing to socket: %s\n", strerror(errno));
        error_number=3;
    }
    else {
        if(strcmp(filename,"ls") == 0){
            file_descriptor = 1; //stdout
            operation_size = filedata_size;
        }
        else{
            operation_size = BUFFER_SIZE;
            file_descriptor = open(filename, O_CREAT|O_RDWR,(mode_t)0644);
        }
        while (transfer_complete == false) {
            nbytes_read = SSL_read(ssl, local_buffer, operation_size);
            if (nbytes_read < 0){
                fprintf(stderr, "Client: Error reading from socket: %s\n", strerror(errno));
                error_number = 7;
            }
            else{
                if (nbytes_read == 0) {
                    printf("\n***Request Complete - Connection Terminated by Server***\n");
                    transfer_complete = true;
                }
                sscanf(local_buffer, "ERROR: %d", &error_number);
                if (error_number == 0){
                    write(file_descriptor, local_buffer, operation_size);
                }
                else{
                    transfer_complete = true;
                }
            }
            bzero(local_buffer, BUFFER_SIZE);
        }
        if(strcmp(filename,"ls") == 0){
            close(file_descriptor);
        }
    }
    return error_number;
}

//sets active server to use for socket to determine if backup server should be used.
int setActiveServer() {
  int sockfd;
  // Creates the underlying TCP socket connection to the remote host
  sockfd = create_socket(DEFAULT_HOST, DEFAULT_PORT);
  if(sockfd > 0)
    fprintf(stderr, "Client: Established TCP connection to '%s'\n", DEFAULT_HOST);
  // The first attempt to connect did not succeed; tries the backup server
  else {
    //printf("Trying backup server on port %u\n", DEFAULT_PORT);
    sockfd = create_socket(BACKUP_HOST, BACKUP_PORT);
    if(sockfd > 0)
      fprintf(stderr, "Client: Established TCP connection to '%s'\n", BACKUP_HOST);
    else {
      fprintf(stderr, "Client: Could not establish TCP connection to %s\n", BACKUP_HOST);
      exit(EXIT_FAILURE);
    }
  }
  return sockfd;
}

//returns true/false if password is authenticated
bool checkPassword(char* userInput) {
    char hashed_input[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    bool authenticated = false;
    int fd;
    int bytesRead=0;

    sprintf(hashed_input,"%s",encrypt(userInput, hashed_input));
    fd = open("passwd", O_RDONLY);
    while ((bytesRead = read(fd, buffer, BUFFER_SIZE) > 0)) {
	    write(fd, buffer, bytesRead);
    }
    if(strcmp(hashed_input,buffer)==0){
        authenticated = true;
    }
    return authenticated;
}


//returns a char array containing the hashed input
char* encrypt(char *input, char output[65]){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    ssize_t bytesRead=1;;
    SHA256_CTX SHAbuffer;
    output[64] = 0;

    SHA256_Init(&SHAbuffer);
    SHA256_Update(&SHAbuffer, input, sizeof(input));
    SHA256_Final(hash, &SHAbuffer);

    for(int i = 0; i< SHA256_DIGEST_LENGTH; i++){
		sprintf(output + (i * 2), "%02x", hash[i]);
    }
    return output;
}