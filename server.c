#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h> 
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define PAGE_SIZE getpagesize()

typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;

typedef struct data_info
{
	size_t string_sizes[3];
	size_t array_size;
	size_t buff_size;
	size_t total_size;
	int syscall_number;
}data_info;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "syscall_param.h"
//for testing
#include <sys/stat.h>
#include <fcntl.h>
//
#define PORT 1234

#define ARG_SIZE(syscall_number, arg_num) syscall_table[syscall_number].argv[arg_num].arg_size
#define ARG_FLAG(syscall_number, arg_num) syscall_table[syscall_number].argv[arg_num].flag
#define ARGS_NUMBER(syscall_number) syscall_table[syscall_number].argc

int extract_args(unsigned long long* param, void* str, data_info *info);
void *execute_syscall(void *client_sock);
int init_data_info(data_info *info);


int main()
{
	SOCKET sock;
	SOCKADDR_IN sin;
	socklen_t recsize = sizeof(sin);
	SOCKET csock;
	SOCKADDR_IN csin;
    socklen_t crecsize = sizeof(csin);
    SOCKET *client_sock;

    int sock_err;
    
	sock = socket(AF_INET, SOCK_STREAM, 0);
	
	if(sock == INVALID_SOCKET) printf("deal with error later");
	/*Initialisation*/
	sin.sin_addr.s_addr = htonl(INADDR_ANY); 
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	
	sock_err = bind(sock, (SOCKADDR*)&sin, sizeof(sin));

	sock_err = listen(sock, 5);
	if (sock_err) perror("listen");

	//receive the syscall parameters in the structure new_info from the client
	while(1)
	{
		csock = accept(sock, (SOCKADDR*)&csin, &crecsize);
		pthread_t client_thread;
		client_sock = malloc( sizeof(int));
		*client_sock = csock;

		pthread_create( &client_thread, NULL, execute_syscall, (void*) client_sock);
		pthread_join(client_thread, NULL);
	}
	close(csock);
	close(sock);
	
	return 0;	
}

int extract_args(unsigned long long* param, void* str, data_info *info)
{
	int arg_num;
	int syscall_number = info->syscall_number;
	size_t size_counter = 0;
	int string_counter = 0;
	int i ;
	size_t array_size = 0;
	unsigned long long *data_ptr = NULL;

	for (i = 0; i < 6; ++i)
	{
		param[i] = 0;///initaliser à zero pour ne pas avoir des fausse valeur
	}
	for (arg_num = 0; arg_num < syscall_table[syscall_number].argc; ++arg_num)
	{
		switch(ARG_FLAG(syscall_number, arg_num))
		{
			case VT:
				memcpy(param + arg_num, str + size_counter, ARG_SIZE(syscall_number, arg_num));
				size_counter += ARG_SIZE(syscall_number, arg_num);
				break;
			case AT:
				param[arg_num] = (unsigned long long) (str + size_counter);
				array_size = info->array_size;
				size_counter += (array_size * ARG_SIZE(syscall_number, arg_num));
				break;
			case MT:
				array_size = info->array_size;
				if (array_size == UNDEFINED_SIZE)
				{
					array_size = info->string_sizes[string_counter] ;
					++string_counter;
				}
				data_ptr = (unsigned long long *) malloc(array_size * sizeof(unsigned long long));
				param[arg_num] = (unsigned long long) data_ptr;
				for (i = 0; i < array_size; ++i)
					{
						*(data_ptr + i* sizeof(unsigned long long)) = (unsigned long long)(str + size_counter);// I have to verify if it's "+i" or "+i*size" and if I can use it as array
						if (syscall_number == SYS_io_submit)
						{
							size_counter += ARG_SIZE(syscall_number, arg_num);
						}
						if (syscall_number == SYS_move_pages)
						{
							size_counter += PAGE_SIZE;
						}
						if (syscall_number == SYS_execve)
						{
							size_counter += strlen((char *)(str + size_counter)) + 1;
						}
					}		
				break;
			case PT:
				param[arg_num] = (unsigned long long) (str + size_counter);
				if (ARG_SIZE(syscall_number, arg_num) == UNDEFINED_SIZE)
				{
					size_counter += info->buff_size;
				}
				else
				{
					size_counter += ARG_SIZE(syscall_number, arg_num);
				}
				break;
			case ST:
				param[arg_num] = (unsigned long long) (str + size_counter);
				size_counter += info->string_sizes[string_counter];
				++string_counter;
				break;
		}
	}
	return 0;
}

void *execute_syscall(void *client_sock)
{
	SOCKET csock = *(int*)client_sock;
	int syscall_number; 
	void* recv_data = NULL;
	unsigned long long params[6];
	data_info info;
	int syscall_return_value;
	char buffer[32]="you are connected\n";

	send(csock, buffer, 32, 0);
	while(1)
	{
		init_data_info(&info);
		recv(csock, &info, sizeof(data_info), 0);
		syscall_number = info.syscall_number;

		if (syscall_number == SYS_exit || syscall_number == SYS_exit_group)
			{
				printf("\n************** The application syscalls have been executed successfully **************\n");
				return NULL;
			}
		if (ARGS_NUMBER(syscall_number) == 0)
		{
			syscall_return_value = syscall(syscall_number);
			send(csock, &syscall_return_value, sizeof(int), 0);
			printf("%d\n", syscall_return_value);
		}
		else
		{
			recv_data = malloc(info.total_size);
			recv(csock, recv_data, info.total_size, 0);
			extract_args(params, recv_data, &info);
			if (syscall_number == 0)
			{
				syscall_return_value = syscall(syscall_number, params[0], params[1], params[2], params[3], params[4], params[5]);
			}
			else
			{
				syscall_return_value = syscall(syscall_number, params[0], params[1], params[2], params[3], params[4], params[5]);
			}
			printf("the syscall is %d with returned value = %d\n",info.syscall_number, syscall_return_value);
			printf("================================================================================================\n");
			//test open()
			/*char *new_buf = (char *)malloc(80);
			read(syscall_return_value, new_buf, 79);
			printf("le fichier est: %s ===>contenant: %s\n", (char *)params[0], new_buf);
			*/
			recv_data = realloc(recv_data, info.total_size + sizeof(int));
			memcpy(recv_data +info.total_size, &syscall_return_value, sizeof(int));
			send(csock, recv_data, info.total_size + sizeof(int), 0);
		}
	}
	return NULL;
}

int init_data_info(data_info *info)
{
	int i;
	for (i = 0; i < 3; ++i)
	{
		info->string_sizes[i] = 0;
	}
	info->array_size = 0;
	info->buff_size = 0;
	info->total_size = 0;
	info->syscall_number = 0;
	return 0;
}
