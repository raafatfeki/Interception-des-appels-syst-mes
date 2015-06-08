typedef int sys_size_t;
typedef enum arg_options
{
	POINTER_TYPE, STRING_TYPE, VALUE_TYPE, ARRAY_TYPE, MATRIX_TYPE
}arg_options;

typedef enum size_options
{
	TOTAL_SIZE, PREDICTABLE_SIZE, NOT_PREDICTABLE_SIZE
}size_options;

typedef struct syscall_arg_info
{
	arg_options flag;
	sys_size_t arg_size;
}arg_info;

typedef struct syscall_size_info
{
	size_options flag;
	sys_size_t total_args_size;
}syscall_size_info;

typedef struct syscall_info
{
	sys_size_t argc;
	syscall_size_info args;
	arg_info argv[6];
}syscall_info;

/* Define args type Flags*/
#define PT POINTER_TYPE
#define ST STRING_TYPE
#define VT VALUE_TYPE
#define AT ARRAY_TYPE
#define MT MATRIX_TYPE

/* Define syscall size Flags*/
#define TS TOTAL_SIZE
#define PS PREDICTABLE_SIZE
#define NPS NOT_PREDICTABLE_SIZE

#define NOT_IMPLEMENTED -1
#define UNDEFINED_SIZE -1

static const syscall_info syscall_table[] = {
#include "syscall_info.h"
};





/*
struct stat, struct pollfd, struct sigaction, sigset_t, struct iovec, struct timeval, struct shmid_ds ,struct timespec, struct itimerval
struct sockaddr ,struct msghdr, struct rusage, struct new_utsname, struct sembuf ,struct msgbuf, struct msqid_ds, struct linux_dirent, 
struct timeval, struct timezone, struct rlimit, struct rusage,struct sysinfo, struct tms, struct timespec, struct utimbuf, struct ustat
,struct statfs, struct sched_param, struct __sysctl_args, struct task_struct, struct timex, struct rlimit, struct io_event, struct iocb
struct linux_dirent64, struct sigevent,struct itimerspec, struct itimerspec, struct epoll_event, struct mq_attr, struct kexec_segment,
struct siginfo, struct pollfd ,struct robust_list_head, struct iovec , struct perf_event_attr, struct rlimit64,struct file_handle
struct mmsghdr,struct getcpu_cache, 

int, unsigned int, size_t, umode_t, char, off_t , unsigned long,  loff_t, fd_set, unsigned char, key_t, void, pid_t, long, umode_t, uid_t , gid_t, 
cap_user_header_t, cap_user_data_t, sigset_t, siginfo_t, stack_t, qid_t, time_t,u32, struct user_desc, aio_context_t
u64,  clockid_t, timer_t,   mqd_t, key_serial_t, __s32, fd_set __user , sigset_t , __u64, 
 */

