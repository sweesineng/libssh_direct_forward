# libssh_direct_forward
Example using libssh to do TCP direct forward

Compile :  
gcc main.c -o df -lssh

Usage :  
./df [-d debug] [-l local:port] [-r remote:port] [-s server:port] [-u username]
