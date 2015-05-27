# Interception-des-appels-syst-mes
1) Compile the server:
gcc -pthread -o server server.c
2) Compile the client:
If you want to test the helloworld:
===> gcc -DHELLO_TEST -o client client.c
If you want to test the helloworld:
===> gcc -DSTAT_TEST -o client client.c

NB:
The helloworld and the stat examples are compiled statically.
