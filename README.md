# Distributed MP3 file sharing system
### By Lincoln Lorscheider, Kaycee Valdez, and Bryant Hanks
####-This system consists of three files.
  1. The Client (ssl-client.c)
  2. The default server (ssl-server.c)
  3. The backup server (backup-server.c)
- Requirements to run:
  - In the root directory, there must be:
    - cert.pem
    - key.pem
  - openSSL

## Instructions:
1. Add your own cert.pem and key.pem to the root directory
2. from the shell, run "make"
3. run ./ssl-server, ./backup-server, or both
4. run ./ssl-client
5. enter the password (which is the word password, in all lower case)
6. type "ls" to get a list of all the files in the mp3 directory
7. to download a file, type the filename (including the extension) after the client prompt (for example: Hound_Dog-Big_Mama_Thornton.mp3 )
8. Each client connection closes after a single server response
9. The requested file will be downloaded to the working directory of ssl-client
