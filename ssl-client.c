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
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>

#define DEFAULT_PORT        4433
#define BACKUP_PORT         4434
#define DEFAULT_HOST        "localhost"
#define BACKUP_HOST         "localhost"
#define MAX_HOSTNAME_LENGTH 256
#define BUFFER_SIZE         512
#define MAX_FILENAME_LENGTH 250
#define PASSWORD_LENGTH     32
#define USERNAME_LENGTH     32
#define HASH_LENGTH         264
#define SEED_LENGTH         8

//Declare function prototypes
int download_file(SSL *ssl, const char* filename);
int listFiles(SSL *ssl);
void getPassword(char* password);
bool checkPassword (const char* password);// See answer @ https://stackoverflow.com/questions/10273414/library-for-passwords-salt-hash-in-c
int setActiveServer(); //this is a wrapper on create_socket that returns sockfd for the successful connection
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
  int               status;
    //below is for password section
  char  bufferPW[USERNAME_LENGTH + HASH_LENGTH + 1];
  char  password[PASSWORD_LENGTH];
  char  username[USERNAME_LENGTH];
  char  hash[HASH_LENGTH];

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
  // **** kaycee should insert her setActiveServer call here ***

  // Create the underlying TCP socket connection to the remote host
  sockfd = setActiveServer();
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

    /*
  // **** Bryant should insert his checkPassword() call here, maybe inside a while loop until it's auth'd ***
    const char *const seedchars = "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz";
    unsigned long int seed[2];

    //"$5$ selects the SHA256 algorithm. The
    // length of this char array is the seed length plus 3 to account for
    // the identifier and two '$" separators
    char salt[] = "$5$........";

    // Generate a (not very) random seed.
    seed[0] = time(NULL);
    seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

    // Convert the salt into printable characters from the seedchars string
    for (int i = 0; i < 8; i++)
    salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

    // Enter the username that will be stored with the hash
    fprintf(stdout, "Enter username: ");
    fgets(username, USERNAME_LENGTH, stdin);
    username[strlen(username)-1] = '\0';

    // Enter the password
    fprintf(stdout, "Enter password: ");
    getPassword(password);

    // Now we create a cryptographic hash of the password with the SHA256
    // algorithm using the generated salt string
    strncpy(hash, crypt(password, salt), HASH_LENGTH);

    // Let's just get rid of that password since we're done with it
    bzero(password, PASSWORD_LENGTH);

    fprintf(stdout, "\n");

    sprintf(bufferPW, "%s,%s\n", username, hash);

    //send username and password to server which will read from a file and compare. After comparing send back 0 for matching
    status = checkPassword(ssl, bufferPW);

    if(status = 0){
    printf("Username & Password Accepted\n");
    status = null;
    exit();
    }
    else{
    printf("Invalid Username or Password\n");
    }
  
  */
    //get filename from user
    printf("Please enter filename to request from server (filename must not have spaces), or type 'ls' to receive a list of available files: ");
    fgets(buffer, BUFFER_SIZE-1, stdin);
    buffer[strlen(buffer)-1] = '\0';
    status = download_file(ssl, buffer);
    switch (status){
        case 0:
            printf("%s downloaded\n", buffer);
            exit();
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
        case 10:
            printf("SERVER ERROR: Could not open MP3 directory\n");
        default:
            printf("Undefined Error Code: %d\n", status);
		}
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
/*
int listFiles(SSL *ssl, const char* ls){
    //int status = 0;
    //int error_number;
    //char request[BUFFER_SIZE];
    //char local_buffer[BUFFER_SIZE];
    // request = "LIST *.mp3"
	
	int nbytes_written;
    int nbytes_read;
    int file_descriptor;
    int status = 0;
    int error_number;
    char request[BUFFER_SIZE];
    char local_buffer[BUFFER_SIZE];
    bool file_complete = false;

    sprintf(request,"GET: %s", ls); //append user-input filepath to appropriate request type (in order to test RPC format error detection, change to something other than GET and build/run)
	nbytes_written = SSL_write(ssl,request,BUFFER_SIZE);//send request to server
    if (nbytes_written < 0)
        fprintf(stderr, "Client: Error writing to socket: %s\n", strerror(errno));
    else {
        file_descriptor = open(ls, O_CREAT|O_RDWR,(mode_t)0644);
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
*/
// Kaycee's code for setActiveServer
int setActiveServer() {
  int sockfd;
  // Creates the underlying TCP socket connection to the remote host
  sockfd = create_socket(DEFAULT_HOST, DEFAULT_PORT);

  if(sockfd != 0)
    fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", DEFAULT_HOST, DEFAULT_PORT);

  // The first attempt to connect did not succeed; tries the backup server
  else {
    printf("Trying backup server on port %u\n", DEFAULT_PORT);
    sockfd = create_socket(DEFAULT_HOST, DEFAULT_PORT);
    if(sockfd != 0)
      fprintf(stderr, "Client: Established TCP connection to '%s' on port %u\n", BACKUP_HOST, BACKUP_PORT);
    else {
      fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", BACKUP_HOST, BACKUP_PORT);
      exit(EXIT_FAILURE);
    }
  }
  return sockfd;
}
/*
void getPassword(char* password) {
    static struct termios oldsettings, newsettings;
    int c, i = 0;

    // Save the current terminal settings and copy settings for resetting
    tcgetattr(STDIN_FILENO, &oldsettings);
    newsettings = oldsettings;

    // Hide, i.e., turn off echoing, the characters typed to the console 
    newsettings.c_lflag &= ~(ECHO);

    // Set the new terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &newsettings);

    // Read the password from the console one character at a time
    while ((c = getchar())!= '\n' && c != EOF && i < HASH_LENGTH)
      password[i++] = c;
    
    password[i] = '\0';

    // Restore the old (saved) terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldsettings);
}

bool checkPassword(SSL *ssl, const char* UandP){
	int nbytes_written;
    int nbytes_read;
    int file_descriptor;
    bool status = false;
    int error_number;
    char request[BUFFER_SIZE];
    char local_buffer[BUFFER_SIZE];
    bool file_complete = false;

    sprintf(request,"UP: %s", UandP); 
    nbytes_written = SSL_write(ssl,request,BUFFER_SIZE);//send request to server
    if (nbytes_written < 0)
        fprintf(stderr, "Client: Error writing to socket: %s\n", strerror(errno));
    else {
        //file_descriptor = open(filename, O_CREAT|O_RDWR,(mode_t)0644);
        //while (file_complete==false) {
            nbytes_read = SSL_read(ssl, local_buffer, BUFFER_SIZE);
            if (nbytes_read < 0)
                fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
            //else if (nbytes_read == 0) {
            //    printf("Connection Terminated by Server\n");
            //    file_complete = true;
            //}
            else {
                error_number = sscanf(local_buffer, "ERROR: %d", &status);
                //if (error_number == 0){
                    //write(file_descriptor, local_buffer, BUFFER_SIZE);
                //}
                //else{
                //    file_complete = true;
                //}
            }
            bzero(local_buffer, BUFFER_SIZE);
        //}
        //close(file_descriptor);
    }
    return status;
}
*/