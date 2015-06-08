#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <unistd.h>

#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define PORT 1234
#define PAGE_SIZE getpagesize()
#define RETURN_SIZE 4
#define NULL_CHAR_SIZE 1
#ifndef UNPREDICT_SIZE
#define UNPREDICT_SIZE 1024
#endif

typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr SOCKADDR;

typedef struct data_info
{
	size_t string_sizes[3]; // For the MT type the string_size contains the size of the strings_list
	size_t array_size;
	size_t buff_size;
	size_t total_size;
	int syscall_number;
}data_info;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include "syscall_param.h"
#include <sys/stat.h>
#include <poll.h>

const int long_size = sizeof(long);
#define PTRACE_ERROR -1
#define ARG_SIZE(syscall_number, arg_num) syscall_table[syscall_number].argv[arg_num].arg_size
#define ARG_FLAG(syscall_number, arg_num) syscall_table[syscall_number].argv[arg_num].flag
#define SYS_INFO_FLAG(syscall_number) syscall_table[syscall_number].args.flag
#define SYS_INFO_SIZE(syscall_number) syscall_table[syscall_number].args.total_args_size
#define ARGS_NUMBER(syscall_number) syscall_table[syscall_number].argc

void* set_syscall_data(pid_t child, int syscall_number, unsigned long long param[], data_info *info);
static size_t get_data(pid_t child, long addr, size_t len, void **str, size_t *str_size, size_t *max_str_size);
static size_t get_string(pid_t child, long addr, size_t len, void **str, size_t *str_size, size_t *max_str_size);
static int put_data(pid_t child, long addr, void *str, size_t len);
int update_registers(pid_t child, unsigned long long *params, void *str, data_info *info, struct user_regs_struct *regs, unsigned long long return_value);
void getdata(pid_t child, long addr, char *str, int len);
int ptrace_get_register(pid_t child, unsigned long long *params, struct user_regs_struct *regs);
int ptrace_set_register(pid_t child, unsigned long long *params, struct user_regs_struct *regs, unsigned long long return_value);
int send_syscall(SOCKET sock, void **syscall_data, data_info *info);
size_t get_buf_size(pid_t child, int syscall_number, unsigned long long *params);
int init_data_info(data_info *info);
size_t get_array_size(int syscall_number, unsigned long long *params);
long get_matrix_data(pid_t child, long addr, long len, void **str, size_t *str_size, size_t data_size, size_t *max_str_size);
int put_matrix_data(pid_t child, long addr, long len, void *str, size_t data_size);

int main()
{
	/* Deal with the sockets */
	SOCKET sock;
	SOCKADDR_IN sin;
	char buffer[32]="";

	sock = socket(AF_INET, SOCK_STREAM, 0);
	
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	if(connect(sock, (SOCKADDR*)&sin, sizeof(sin)) != SOCKET_ERROR)
            printf("Connexion  %s sur le port %d\n", inet_ntoa(sin.sin_addr), htons(sin.sin_port));
    else
				printf("Impossible de se connecter\n");
				
	if(recv(sock, buffer, 32, 0) != SOCKET_ERROR)
                printf("Recu : %s\n", buffer);
	
	/*---------------------------- Extract the arguments from write syscall------------------------------*/
    pid_t child_process;
	int return_value;
	int status; // to wait for child process
	long orig_rax; //The syscall number called 
	unsigned long long params[6];
	unsigned long long fakeparams[6] = {0};
	int insyscall = 0;
    struct user_regs_struct regs;
	void * syscall_data = NULL;// pointer to the exchanged data
	data_info info;
	
	child_process = fork();
		if(child_process == 0) 
			{
				/* Initiate the child to be traced by his parent */
				ptrace(PTRACE_TRACEME, 0, NULL, NULL);
				#ifdef STAT_TEST
				execl("./stat", "stat", NULL);
				#endif
				#ifdef HELLO_TEST
				execl("./helloworld_static", "helloworld_static", NULL);
				#endif
			}
		else
			{
				while(1) 
					{

						wait(&status); // is equivalent to waitpid(-1, &status, 0) meaning wait for any child process
						if(WIFEXITED(status)) break; //returns true if the child terminated normally
						
						orig_rax = ptrace(PTRACE_PEEKUSER, child_process, 8 * ORIG_RAX, NULL);
						if (orig_rax !=SYS_execve && orig_rax != SYS_mmap && orig_rax !=SYS_arch_prctl && orig_rax != SYS_mprotect && orig_rax != SYS_brk) //
						{
						if(insyscall == 0) // Syscall before execution
							{
								insyscall = 1;
								/* Getting the 6 parameters from registers. */
								ptrace_get_register(child_process, params, &regs);
								/* Extract data from the child memory */
								syscall_data = set_syscall_data(child_process, orig_rax, params, &info);
								if (orig_rax == SYS_exit || orig_rax == SYS_exit_group)
								{
									/* Send data to server */
									send(sock, &info , sizeof(data_info), 0);
								}
								else
								{
									/* Make the syscall in the child fail */
									ptrace_set_register(child_process, fakeparams, &regs, -12);
								}
								
							}
							
						else // Syscall After execution
							{ 
								insyscall = 0;
								/* Send data to server */
								return_value = send_syscall(sock, &syscall_data, &info);
								/* Update the child memory with new data */
								update_registers(child_process, params, syscall_data, &info, &regs, (unsigned long long)return_value);
								/* Get the registers content after syscall execution */
								ptrace(PTRACE_GETREGS, child_process, NULL, regs);
								#ifdef HELLO_TEST
								printf("Syscall_number=%lld\nreturned_value=%lld\n", regs.orig_rax, regs.rax);	
								printf("===========================================================================\n");
								#endif
								//printf("2============\norig_rax=%lld\nrax=%lld\nparam1=%lld\nparam2=%lld\nparam3=%lld\nparam4=%lld\nparam5=%lld\nparam6=%lld\n", 
								//	regs.orig_rax, regs.rax, regs.rdi,regs.rsi,regs.rdx,regs.r10,regs.r8,regs.r9);
								// Update registers with new arguments
								//printf("3============\norig_rax=%lld\nrax=%lld\nparam1=%lld\nparam2=%lld\nparam3=%lld\nparam4=%lld\nparam5=%lld\nparam6=%lld\n", 
								//	regs.orig_rax, regs.rax, regs.rdi,regs.rsi,regs.rdx,regs.r10,regs.r8,regs.r9);
								// ============> for testing write the syscall returns 12 (number of char in "hello world\n") and getpid() (same pid in server and client)
								/*#ifdef OPEN_TEST
								if (orig_rax == SYS_open)
								{
									printf("open========>%lld\n", regs.rax);
								}
								if (orig_rax == SYS_close)
									printf("close========>%lld\n", params[0]);
								if (orig_rax == SYS_read)
								{
									void *str = NULL;
									size_t sizea = 0;
									get_data(child_process, params[1], 800, &str, &sizea);
									printf("read========+>%s \n", (char *)str );
								}
								#endif	*/
								// ============> for testing stat 
								#ifdef STAT_TEST
								if (orig_rax == SYS_stat)
								{
									printf("This is the result of the syscall stat after updating the child memory\nif the values are the same with those printed in the server than the syscall has succeeded\n");
									printf("==============================================================\n");
									ptrace(PTRACE_GETREGS, child_process, NULL, regs);
									void *str = malloc(144);
									size_t sizea = 0;
									size_t max = 144;
									get_data(child_process, params[1], 144, &str, &sizea, &max);
									printf("st_dev=%d\nst_ino=%d\nst_mode=%d\nst_nlink=%d\nst_uid=%d\nst_gid=%d\nst_rdev=%d\nst_size=%d\nst_blksize=%d\nst_blocks=%d\n", 
									(int) ((struct stat *)str)->st_dev,(int) ((struct stat *)str)->st_ino ,(int) ((struct stat *)str)->st_mode ,
									(int) ((struct stat *)str)->st_nlink ,(int) ((struct stat *)str)->st_uid ,(int) ((struct stat *)str)->st_gid ,
									(int) ((struct stat *)str)->st_rdev ,(int) ((struct stat *)str)->st_size ,(int) ((struct stat *)str)->st_blksize,
									(int) ((struct stat *)str)->st_blocks );
								}
								#endif							
							}
							
						}
						ptrace(PTRACE_SYSCALL, child_process, NULL, NULL);
					}
			}
	close(sock);
	return 0;
}




void* set_syscall_data(pid_t child, int syscall_number, unsigned long long param[], data_info *info)
{
	int string_counter = 0;
	void* data_to_send = NULL;
	size_t total_size = 0;
	int arg_num;
	size_t buff_size = 0;
	size_t array_size = 0;
	size_t predict_size = 0;
	size_t max_str_size = 0;
	init_data_info(info);

	switch(SYS_INFO_FLAG(syscall_number))
	{
		case TS:
			max_str_size = SYS_INFO_SIZE(syscall_number) + RETURN_SIZE;
			data_to_send = malloc(max_str_size);
			break;
		case PS:
		case NPS:
			for (arg_num = 0; arg_num < syscall_table[syscall_number].argc; ++arg_num)
			{
				if ((ARG_FLAG(syscall_number, arg_num) == PT) && (ARG_SIZE(syscall_number, arg_num) == UNDEFINED_SIZE))
				{ 
					predict_size += get_buf_size(child, syscall_number, param);
				}
				if (ARG_FLAG(syscall_number, arg_num) == AT)
				{
					predict_size += (get_array_size(syscall_number, param) * ARG_SIZE(syscall_number, arg_num));
				}
				if (ARG_FLAG(syscall_number, arg_num) == MT)
				{
					printf("Deal with it later, special cases\n");
				}
				if (ARG_FLAG(syscall_number, arg_num) == ST)
				{
					switch(syscall_number)
					{
						case SYS_sethostname:
						case SYS_setdomainname:
						case SYS_readlink:
						case SYS_listxattr:
						case SYS_llistxattr:
						case SYS_readlinkat:
						case SYS_getcwd:
						case SYS_read:
						case SYS_write:
						case SYS_pread64:
						case SYS_pwrite64:
						case SYS_syslog://// to verify, there are some ambiguities 
						case SYS_flistxattr:
						case SYS_lookup_dcookie:
						case SYS_mq_timedreceive:
						case SYS_getsockopt:
						case SYS_setsockopt:
						case SYS_mq_timedsend:
							predict_size += get_buf_size(child, syscall_number, param) + NULL_CHAR_SIZE;
							break;
					}
				}
			}
			if(SYS_INFO_FLAG(syscall_number) == PS)
			{
				max_str_size = SYS_INFO_SIZE(syscall_number) + predict_size + RETURN_SIZE;
				data_to_send = malloc(max_str_size);
			}
			else
			{
				max_str_size = SYS_INFO_SIZE(syscall_number) + predict_size + UNPREDICT_SIZE + RETURN_SIZE;
				data_to_send = malloc(max_str_size);
			}
			break;
	}

	if (ARGS_NUMBER(syscall_number) != 0)
	{
		for (arg_num = 0; arg_num < syscall_table[syscall_number].argc; ++arg_num)
		{
			switch(ARG_FLAG(syscall_number, arg_num))
			{
				case VT:
					memcpy(data_to_send + total_size, param + arg_num, ARG_SIZE(syscall_number, arg_num));
					total_size += ARG_SIZE(syscall_number, arg_num);
					break;
				case AT:
					array_size = get_array_size(syscall_number, param);
					info->array_size = array_size;
					get_data(child, param[arg_num], array_size * ARG_SIZE(syscall_number, arg_num), &(data_to_send), &(total_size), &(max_str_size));
					break;
				case MT:
					array_size = get_array_size(syscall_number, param);
					info->array_size = array_size;
					if (syscall_number == SYS_move_pages)
					{
						get_matrix_data(child, param[arg_num], array_size, &(data_to_send), &(total_size), PAGE_SIZE, &(max_str_size));
					}
					if (syscall_number == SYS_io_submit)
					{
						get_matrix_data(child, param[arg_num], array_size, &(data_to_send), &(total_size), ARG_SIZE(syscall_number, arg_num), &(max_str_size));
					}
					if (syscall_number == SYS_execve)
					{
						info->string_sizes[string_counter] = get_matrix_data(child, param[arg_num], array_size, &(data_to_send), &(total_size), ARG_SIZE(syscall_number, arg_num), &(max_str_size));
						++string_counter;
					}
					break;
				case PT:
					if (ARG_SIZE(syscall_number, arg_num) == UNDEFINED_SIZE)
					{
						buff_size = get_buf_size(child, syscall_number, param);
						get_data(child, param[arg_num], buff_size, &(data_to_send), &(total_size), &(max_str_size));
					}
					else
					{
						get_data(child, param[arg_num], ARG_SIZE(syscall_number, arg_num), &(data_to_send), &(total_size), &(max_str_size));
					}
					break;
				case ST:
					switch(syscall_number)
					{
						case SYS_sethostname:
						case SYS_setdomainname: 
						case SYS_readlink:
						case SYS_listxattr:
						case SYS_llistxattr:
						case SYS_readlinkat:
							if (string_counter == 0)
							{
								info->string_sizes[string_counter] = get_string(child, param[arg_num], UNDEFINED_SIZE, &(data_to_send), &(total_size), &(max_str_size));
							}
							else
							{
								buff_size = get_buf_size(child, syscall_number, param);
								info->string_sizes[string_counter] = get_string(child, param[arg_num], buff_size, &(data_to_send), &(total_size), &(max_str_size));
							}
							break;
						case SYS_getcwd:
						case SYS_read:
						case SYS_write:
						case SYS_pread64:
						case SYS_pwrite64:
						case SYS_syslog://// to verify, there are some ambiguities 
						case SYS_flistxattr:
						case SYS_lookup_dcookie:
						case SYS_mq_timedreceive:
						case SYS_getsockopt:
						case SYS_setsockopt:
						case SYS_mq_timedsend:
							buff_size = get_buf_size(child, syscall_number, param);
							info->string_sizes[string_counter] = get_string(child, param[arg_num], buff_size, &(data_to_send), &(total_size), &(max_str_size));
							break;
						default:
							info->string_sizes[string_counter] = get_string(child, param[arg_num], UNDEFINED_SIZE, &(data_to_send), &(total_size), &(max_str_size));
							break;
					}
					++string_counter;
					break;
			}
		}
	}
	info->syscall_number = syscall_number;
	info->total_size = total_size;
	return data_to_send; //Deal with errors later
}

int update_registers(pid_t child, unsigned long long *params, void *str, data_info *info, struct user_regs_struct *regs, unsigned long long return_value)
{
	int arg_num;
	int syscall_number = info->syscall_number;
	size_t size_counter = 0;
	int string_counter = 0;
	size_t buff_size = 0;
	size_t array_size = 0;

	if (ARGS_NUMBER(syscall_number) != 0)
	{
		for (arg_num = 0; arg_num < syscall_table[syscall_number].argc; ++arg_num)
		{
			switch(ARG_FLAG(syscall_number, arg_num))
			{
				case VT:
					params[arg_num] = 0;
					memcpy(params + arg_num, str + size_counter, ARG_SIZE(syscall_number, arg_num));
					size_counter += ARG_SIZE(syscall_number, arg_num);
					break;
				case AT:
					array_size = get_array_size(syscall_number, params);
					put_data(child, params[arg_num], str + size_counter, array_size * ARG_SIZE(syscall_number, arg_num));
					size_counter += (array_size * ARG_SIZE(syscall_number, arg_num));
					break;
				case MT:
					array_size = get_array_size(syscall_number, params);
					if (syscall_number == SYS_io_submit)
					{
						put_matrix_data(child, params[arg_num], array_size, str + size_counter, ARG_SIZE(syscall_number, arg_num));
						size_counter += (array_size * ARG_SIZE(syscall_number, arg_num));
					}
					if (syscall_number == SYS_move_pages)
					{
						put_matrix_data(child, params[arg_num], array_size, str + size_counter, PAGE_SIZE);
						size_counter += (array_size * PAGE_SIZE);
					}
					break;
				case PT:
					if (ARG_SIZE(syscall_number, arg_num) == UNDEFINED_SIZE)
					{
						buff_size = info->buff_size;
						put_data(child, params[arg_num], str + size_counter, buff_size);
						size_counter += buff_size;
					}
					else
					{
						put_data(child, params[arg_num], str + size_counter, ARG_SIZE(syscall_number, arg_num));
						size_counter += ARG_SIZE(syscall_number, arg_num);				
					}	
					break;
				case ST:
					put_data(child, params[arg_num], str + size_counter, info->string_sizes[string_counter]);
					size_counter += info->string_sizes[string_counter];
					++string_counter;
					break;
			}
		}
	}
	ptrace_set_register(child, params, regs, return_value);
	free(str);
	return 0;
}

int ptrace_get_register(pid_t child, unsigned long long *params, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, child, NULL, regs) != PTRACE_ERROR)
	{
		params[0] = regs->rdi;
		params[1] = regs->rsi;
		params[2] = regs->rdx;
		params[3] = regs->r10;
		params[4] = regs->r8;
		params[5] = regs->r9;	
		return 0; 
	}
	return PTRACE_ERROR;
}

int ptrace_set_register(pid_t child, unsigned long long *params, struct user_regs_struct *regs, unsigned long long return_value)
{
	regs->rdi = params[0];
	regs->rsi = params[1];
	regs->rdx = params[2];
	regs->r10 = params[3];
	regs->r8 = params[4];
	regs->r9 = params[5];
	regs->rax = return_value;
	return ptrace(PTRACE_SETREGS, child, NULL, regs); 
}

int send_syscall(SOCKET sock, void **syscall_data, data_info *info)
{
	void *st = *syscall_data;
	int syscall_number = info->syscall_number;

	send(sock, info , sizeof(data_info), 0);
	if (ARGS_NUMBER(syscall_number) == 0)
	{
		recv(sock, &syscall_number, sizeof(int), 0);
	}
	else
	{
		send(sock, st , info->total_size, 0);
		*syscall_data = st;
		recv(sock, st, info->total_size + sizeof(int), 0);
		memcpy(&syscall_number, st +info->total_size, sizeof(int));
	}
	return syscall_number;
}


static size_t get_string(pid_t child, long addr, size_t len, void **str, size_t *str_size, size_t *max_str_size)
{
	int cond = 0;
  	int i, j;
  	void *laddr;
 	void *st = *str;
  	union u {
            long val;
            char chars[long_size];
    }data;
    size_t string_size = 0;
    if (len == UNDEFINED_SIZE)
    {
    	while(cond != -1)
		{
			if (*max_str_size - *str_size - long_size < 0)
			{
				*str = realloc(*str, *str_size + UNPREDICT_SIZE);
				*max_str_size = *str_size + UNPREDICT_SIZE;
			}
			data.val = ptrace(PTRACE_PEEKDATA,child, addr + cond * 8, NULL);
			++cond;
			for (i = 0; i < long_size; ++i)
			{
				if (data.chars[i] == '\0')
				{
					memcpy(st + *str_size, data.chars, i + 1);
					*str_size += i + 1;
					string_size += i + 1;
					cond = -1;
					break;
				}
	      		else
				{
					if (i == long_size -1)
					{
						memcpy(st + *str_size, data.chars, long_size);
						*str_size += long_size;
						string_size += long_size;
					}
				}
			}
		}
		*str =  st;
	}
	else
	{
		string_size = get_data(child, addr, len+1, str, str_size, max_str_size);
	}
  return string_size;
} 

static size_t get_data(pid_t child, long addr, size_t len, void **str, size_t *str_size, size_t *max_str_size)
{
	void *st;
	int i, j;
	long data;

	i = 0;
	j = len / long_size;
	if (*max_str_size - *str_size - len < 0)
	{
		*str = realloc(*str, *str_size + UNPREDICT_SIZE);
		*max_str_size = *str_size + UNPREDICT_SIZE;
	}
	st = *str;
	
	while(i < j) 
	{
		data = ptrace(PTRACE_PEEKDATA,child, addr + i * 8, NULL);
		memcpy(st + *str_size, &data, long_size);
		++i;
		st += long_size;
	}
			

	j = len % long_size;
	if(j != 0) 
	{
		data = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
		memcpy(st + *str_size, &data, j);
	}
	*str_size += len;
	return len;
}
static int put_data(pid_t child, long addr, void *str, size_t len)
{
	void *st;
	int i, j;
	long data;
	i = 0;
	j = len / long_size;
	st = str;
	while(i < j)
	{
		memcpy(&data, st, long_size);
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data);
		++i;
		st += long_size;
	}
	j = len % long_size;
	if(j != 0) 
	{
		data = 0;
		memcpy(&data, st, j);
		ptrace(PTRACE_POKEDATA, child,addr + i * 8, data);
	}
	return 0;
}	

size_t get_buf_size(pid_t child, int syscall_number, unsigned long long *params)
{
	switch(syscall_number)
		{
			case SYS_getcwd:
			case SYS_io_submit:///////!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			case SYS_move_pages:///////!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			case SYS_init_module://not string void *
			case SYS_sethostname:
			case SYS_setdomainname:
			case SYS_poll: // array
				return (size_t)params[1];
				break;
			case SYS_read:
			case SYS_write:
			case SYS_pread64:
			case SYS_pwrite64:
			case SYS_readlink:
			case SYS_syslog://// to verify, there are some ambiguities 
			case SYS_listxattr:
			case SYS_llistxattr:
			case SYS_flistxattr:
			case SYS_lookup_dcookie:
			case SYS_mq_timedreceive:
			case SYS_sendto://not string void *
			case SYS_recvfrom://not string void *
			case SYS_modify_ldt://not string void *
			case SYS_readv: // array
			case SYS_writev: // array
			case SYS_mq_timedsend:
				return (size_t)params[2];
				break;
			case SYS_readlinkat:
			case SYS_setxattr://not string void *
			case SYS_lsetxattr://not string void *
			case SYS_fsetxattr://not string void *
			case SYS_getxattr://not string void *
			case SYS_lgetxattr://not string void *
			case SYS_fgetxattr://not string void *
			case SYS_add_key://not string void *
				return (size_t)params[3];
				break;
			case SYS_setsockopt:
				return (size_t)params[4];
				break;
			case SYS_getsockopt://// the 4 is a pointer to the buf size
				return (size_t) ptrace(PTRACE_PEEKDATA, child, params[4], NULL);
			case SYS_get_robust_list:////!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				return (size_t) ptrace(PTRACE_PEEKDATA, child, params[2], NULL);	
				break;
		}
}

size_t get_array_size(int syscall_number, unsigned long long *params)
{
	switch(syscall_number)
		{
			case SYS_select: // !!!!!!!!!!!!!!! A voir 
			case SYS_getgroups: 
			case SYS_setgroups: 
			case SYS_pselect6: // !!!!!!!!!!!!!!! A voir 
				return (size_t)params[0];
				break;
			case SYS_poll: 
			case SYS_ppoll: 
			case SYS_kexec_load: 
			case SYS_migrate_pages: 
			case SYS_move_pages:
			case SYS_io_submit:
				return (size_t)params[1];
				break;
			case SYS_readv: 
			case SYS_writev: 
			case SYS_semop: 
			case SYS_io_getevents: 
			case SYS_getdents64: 
			case SYS_semtimedop: 
			case SYS_epoll_wait: 
			case SYS_set_mempolicy: 
			case SYS_get_mempolicy: 
			case SYS_vmsplice: 			
			case SYS_epoll_pwait: 	
			case SYS_preadv: 		
			case SYS_pwritev: 		
			case SYS_recvmmsg: 		
			case SYS_sendmmsg: 	
				return (size_t)params[2];
				break;
			case SYS_process_vm_readv:
			case SYS_process_vm_writev:
			/* just for instance */
				if (params[4] > params[2])
				{
					return (size_t) params[4];
				}
				else
				{
					return (size_t)params[2];
				}
				break; 
			case SYS_mbind:
				return (size_t)params[4];
				break; 
			case SYS_pipe: 
			case SYS_pipe2: 
			case SYS_socketpair: 
			case SYS_futimesat: 
				return 2;
				break;	
			case SYS_execve:
				return UNDEFINED_SIZE;
				break; 

		}
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

long get_matrix_data(pid_t child, long addr, long len, void **str, size_t *str_size, size_t data_size, size_t *max_str_size) // for sys_io_submit and sys_move_pages
{
	int i = 0;
	long data_ptr;

	if ((len == UNDEFINED_SIZE) && (data_size == UNDEFINED_SIZE))
	{
		while(1)
		{
			data_ptr = ptrace(PTRACE_PEEKDATA,child, addr + i * 8, NULL);
			if ((void *)data_ptr == NULL)
			{
				break;
			}
			else
			{
				get_string(child, data_ptr, data_size, str, str_size, max_str_size);
			}
			++i;
		}
		return (long)i;
	}
	else
	{
		for (i = 0; i < len; ++i)
		{
			data_ptr = ptrace(PTRACE_PEEKDATA,child, addr + i * 8, NULL); 
			get_data(child, data_ptr, data_size, str, str_size, max_str_size);
		}
	}
	return len;
}

int put_matrix_data(pid_t child, long addr, long len, void *str, size_t data_size)
{
	int i = 0;
	long data_ptr;

	for (i = 0; i < len; ++i)
	{
		data_ptr = ptrace(PTRACE_PEEKDATA,child, addr + i * 8, NULL); 
		put_data(child, data_ptr, str + i * data_size, data_size);
	}
}
