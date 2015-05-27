[0] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_read */
[1] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_write */
[2] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, [2] = {VT, 2}, } },	/* sys_open */
[3] = { 1, { [0] = {VT, 4}, } },	/* sys_close */
[4] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {PT, 144}, } },	/* sys_newstat */
[5] = { 2, { [0] = {VT, 4}, [1] = {PT, 144}, } },	/* sys_newfstat */
[6] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {PT, 144}, } },	/* sys_newlstat */
[7] = { 3, { [0] = {AT, 8}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_poll */
[8] = { 3, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 4}, } },	/* sys_lseek */
[9] = { 6, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, [5] = {VT, 8}} },	/* sys_mmap */
[10] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, } },	/* sys_mprotect */
[11] = { 2, { [0] = {VT, 8}, [1] = {VT, 8}, } },	/* sys_munmap */
[12] = { 1, { [0] = {VT, 8}, } },	/* sys_brk */
[13] = { 4, { [0] = {VT, 4}, [1] = {PT, 152}, [2] = {PT, 152}, [3] = {VT, 8}, } },	/* sys_rt_sigaction */
[14] = { 4, { [0] = {VT, 4}, [1] = {PT, 128}, [2] = {PT, 128}, [3] = {VT, 8}, } },	/* sys_rt_sigprocmask */
[15] = {0, },	/* sys_rt_sigreturn */
[16] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 8}, } },	/* sys_ioctl */
[17] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {VT, 8}, } },	/* sys_pread64 */
[18] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {VT, 8}, } },	/* sys_pwrite64 */
[19] = { 3, { [0] = {VT, 8}, [1] = {AT, 16}, [2] = {VT, 8}, } },	/* sys_readv */
[20] = { 3, { [0] = {VT, 8}, [1] = {AT, 16}, [2] = {VT, 8}, } },	/* sys_writev */
[21] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_access */
[22] = { 1, { [0] = {AT, 4}, } },	/* sys_pipe */
[23] = { 5, { [0] = {VT, 4}, [1] = {PT, 128}, [2] = {PT, 128}, [3] = {PT, 128}, [4] = {PT, 16}, } },	/* sys_select */
[24] = {0, },	/* sys_sched_yield */
[25] = { 5, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_mremap */
[26] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 4}, } },	/* sys_msync */
[27] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {ST, UNDEFINED_SIZE}, } },	/* sys_mincore */
[28] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 4}, } },	/* sys_madvise */
[29] = { 3, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 4}, } },	/* sys_shmget */
[30] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_shmat */
[31] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 112}, } },	/* sys_shmctl */
[32] = { 1, { [0] = {VT, 4}, } },	/* sys_dup */
[33] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_dup2 */
[34] = {0, },	/* sys_pause */
[35] = { 2, { [0] = {PT, 16}, [1] = {PT, 16}, } },	/* sys_nanosleep */
[36] = { 2, { [0] = {VT, 4}, [1] = {PT, 32}, } },	/* sys_getitimer */
[37] = { 1, { [0] = {VT, 4}, } },	/* sys_alarm */
[38] = { 3, { [0] = {VT, 4}, [1] = {PT, 32}, [2] = {PT, 32}, } },	/* sys_setitimer */
[39] = {0, },	/* sys_getpid */
[40] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 8}, [3] = {VT, 8}, } },	/* sys_sendfile */
[41] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_socket */
[42] = { 3, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 4}, } },	/* sys_connect */
[43] = { 3, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {PT, 4}, } },	/* sys_accept */
[44] = { 6, { [0] = {VT, 4}, [1] = {PT, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {VT, 4}, [4] = {PT, 16}, [5] = {VT, 4}} },	/* sys_sendto */
[45] = { 6, { [0] = {VT, 4}, [1] = {PT, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {VT, 4}, [4] = {PT, 16}, [5] = {PT, 4}} },	/* sys_recvfrom */
[46] = { 3, { [0] = {VT, 4}, [1] = {PT, 56}, [2] = {VT, 4}, } },	/* sys_sendmsg */
[47] = { 3, { [0] = {VT, 4}, [1] = {PT, 56}, [2] = {VT, 4}, } },	/* sys_recvmsg */
[48] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_shutdown */
[49] = { 3, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 4}, } },	/* sys_bind */
[50] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_listen */
[51] = { 3, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {PT, 4}, } },	/* sys_getsockname */
[52] = { 3, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {PT, 4}, } },	/* sys_getpeername */
[53] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {AT, 4}, } },	/* sys_socketpair */
[54] = { 5, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, [4] = {VT, 4}, } },	/* sys_setsockopt */
[55] = { 5, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, [4] = {PT, 4}, } },	/* sys_getsockopt */
[56] = { 5, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {PT, 4}, [3] = {VT, 4}, [4] = {PT, 4}, } },	/* sys_clone */
[57] = {0, },	/* sys_fork */
[58] = {0, },	/* sys_vfork */
[59] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {MT, UNDEFINED_SIZE}, [2] = {MT, UNDEFINED_SIZE}, } },	/* sys_execve */
[60] = { 1, { [0] = {VT, 4}, } },	/* sys_exit */
[61] = { 4, { [0] = {VT, 4}, [1] = {PT, 4}, [2] = {VT, 4}, [3] = {PT, 144}, } },	/* sys_wait4 */
[62] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_kill */
[63] = { 1, { [0] = {PT, 390}, } },	/* sys_newuname */
[64] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_semget */
[65] = { 3, { [0] = {VT, 4}, [1] = {AT, 6}, [2] = {VT, 4}, } },	/* sys_semop */
[66] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {VT, 8}, } },	/* sys_semctl */
[67] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_shmdt */
[68] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_msgget */
[69] = { 4, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_msgsnd */
[70] = { 5, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 4}, } },	/* sys_msgrcv */
[71] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 120}, } },	/* sys_msgctl */
[72] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 8}, } },	/* sys_fcntl */
[73] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_flock */
[74] = { 1, { [0] = {VT, 4}, } },	/* sys_fsync */
[75] = { 1, { [0] = {VT, 4}, } },	/* sys_fdatasync */
[76] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 8}, } },	/* sys_truncate */
[77] = { 2, { [0] = {VT, 4}, [1] = {VT, 8}, } },	/* sys_ftruncate */
[78] = { 3, { [0] = {VT, 4}, [1] = {PT, 24}, [2] = {VT, 4}, } },	/* sys_getdents */
[79] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 8}, } },	/* sys_getcwd */
[80] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_chdir */
[81] = { 1, { [0] = {VT, 4}, } },	/* sys_fchdir */
[82] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_rename */
[83] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 2}, } },	/* sys_mkdir */
[84] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_rmdir */
[85] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 2}, } },	/* sys_creat */
[86] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_link */
[87] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_unlink */
[88] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_symlink */
[89] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_readlink */
[90] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 2}, } },	/* sys_chmod */
[91] = { 2, { [0] = {VT, 4}, [1] = {VT, 2}, } },	/* sys_fchmod */
[92] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_chown */
[93] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_fchown */
[94] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_lchown */
[95] = { 1, { [0] = {VT, 4}, } },	/* sys_umask */
[96] = { 2, { [0] = {PT, 16}, [1] = {PT, 8}, } },	/* sys_gettimeofday */
[97] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_getrlimit */
[98] = { 2, { [0] = {VT, 4}, [1] = {PT, 144}, } },	/* sys_getrusage */
[99] = { 1, { [0] = {PT, 112}, } },	/* sys_sysinfo */
[100] = { 1, { [0] = {PT, 32}, } },	/* sys_times */
[101] = { 4, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, } },	/* sys_ptrace */
[102] = {0, },	/* sys_getuid */
[103] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_syslog */
[104] = {0, },	/* sys_getgid */
[105] = { 1, { [0] = {VT, 4}, } },	/* sys_setuid */
[106] = { 1, { [0] = {VT, 4}, } },	/* sys_setgid */
[107] = {0, },	/* sys_geteuid */
[108] = {0, },	/* sys_getegid */
[109] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_setpgid */
[110] = {0, },	/* sys_getppid */
[111] = {0, },	/* sys_getpgrp */
[112] = {0, },	/* sys_setsid */
[113] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_setreuid */
[114] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_setregid */
[115] = { 2, { [0] = {VT, 4}, [1] = {AT, 4}, } },	/* sys_getgroups */
[116] = { 2, { [0] = {VT, 4}, [1] = {AT, 4}, } },	/* sys_setgroups */
[117] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_setresuid */
[118] = { 3, { [0] = {PT, 4}, [1] = {PT, 4}, [2] = {PT, 4}, } },	/* sys_getresuid */
[119] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_setresgid */
[120] = { 3, { [0] = {PT, 4}, [1] = {PT, 4}, [2] = {PT, 4}, } },	/* sys_getresgid */
[121] = { 1, { [0] = {VT, 4}, } },	/* sys_getpgid */
[122] = { 1, { [0] = {VT, 4}, } },	/* sys_setfsuid */
[123] = { 1, { [0] = {VT, 4}, } },	/* sys_setfsgid */
[124] = { 1, { [0] = {VT, 4}, } },	/* sys_getsid */
[125] = { 2, { [0] = {VT, 8}, [1] = {VT, 8}, } },	/* sys_capget */
[126] = { 2, { [0] = {VT, 8}, [1] = {VT, 8}, } },	/* sys_capset */
[127] = { 2, { [0] = {PT, 128}, [1] = {VT, 8}, } },	/* sys_rt_sigpending */
[128] = { 4, { [0] = {PT, 128}, [1] = {PT, 128}, [2] = {PT, 16}, [3] = {VT, 8}, } },	/* sys_rt_sigtimedwait */
[129] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 128}, } },	/* sys_rt_sigqueueinfo */
[130] = { 2, { [0] = {PT, 128}, [1] = {VT, 8}, } },	/* sys_rt_sigsuspend */
[131] = { 2, { [0] = {PT, 24}, [1] = {PT, 24}, } },	/* sys_sigaltstack */
[132] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {PT, 16}, } },	/* sys_utime */
[133] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 2}, [2] = {VT, 4}, } },	/* sys_mknod */
[134] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_uselib */
[135] = { 1, { [0] = {VT, 4}, } },	/* sys_personality */
[136] = { 2, { [0] = {VT, 4}, [1] = {PT, 32}, } },	/* sys_ustat */
[137] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {PT, 120}, } },	/* sys_statfs */
[138] = { 2, { [0] = {VT, 4}, [1] = {PT, 120}, } },	/* sys_fstatfs */
[139] = { 3, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, } },	/* sys_sysfs */
[140] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_getpriority */
[141] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_setpriority */
[142] = { 2, { [0] = {VT, 4}, [1] = {PT, 4}, } },	/* sys_sched_setparam */
[143] = { 2, { [0] = {VT, 4}, [1] = {PT, 4}, } },	/* sys_sched_getparam */
[144] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 4}, } },	/* sys_sched_setscheduler */
[145] = { 1, { [0] = {VT, 4}, } },	/* sys_sched_getscheduler */
[146] = { 1, { [0] = {VT, 4}, } },	/* sys_sched_get_priority_max */
[147] = { 1, { [0] = {VT, 4}, } },	/* sys_sched_get_priority_min */
[148] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_sched_rr_get_interval */
[149] = { 2, { [0] = {VT, 8}, [1] = {VT, 8}, } },	/* sys_mlock */
[150] = { 2, { [0] = {VT, 8}, [1] = {VT, 8}, } },	/* sys_munlock */
[151] = { 1, { [0] = {VT, 4}, } },	/* sys_mlockall */
[152] = {0, },	/* sys_munlockall */
[153] = {0, },	/* sys_vhangup */
[154] = { 3, { [0] = {VT, 4}, [1] = {PT, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_modify_ldt */
[155] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_pivot_root */
[156] = { 1, { [0] = {PT, 80}, } },	/* sys_sysctl */
[157] = { 5, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_prctl */
[158] = { 2, { [0] = {VT, 4}, [1] = {VT, 8}, } },	/* sys_arch_prctl */
[159] = { 1, { [0] = {PT, 208}, } },	/* sys_adjtimex */
[160] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_setrlimit */
[161] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_chroot */
[162] = {0, },	/* sys_sync */
[163] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_acct */
[164] = { 2, { [0] = {PT, 16}, [1] = {PT, 8}, } },	/* sys_settimeofday */
[165] = { 5, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {ST, UNDEFINED_SIZE}, [3] = {VT, 8}, [4] = {ST, UNDEFINED_SIZE}, } },	/* sys_mount */
[166] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_umount */
[167] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_swapon */
[168] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_swapoff */
[169] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, } },	/* sys_reboot */
[170] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_sethostname */
[171] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_setdomainname */
[172] = { 1, { [0] = {VT, 4}, } },	/* sys_iopl */
[173] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 4}, } },	/* sys_ioperm */
[174] = {NOT_IMPLEMENTED, },	/* sys_create_module */
[175] = { 3, { [0] = {PT, UNDEFINED_SIZE}, [1] = {VT, 8}, [2] = {ST, UNDEFINED_SIZE}, } },	/* sys_init_module */
[176] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, } },	/* sys_delete_module */
[177] = {NOT_IMPLEMENTED, },	/* sys_get_kernel_syms */
[178] = {NOT_IMPLEMENTED, },	/* sys_query_module */
[179] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, } },	/* sys_quotactl */
[180] = {NOT_IMPLEMENTED, },	/* sys_nfsservctl */
[181] = {NOT_IMPLEMENTED, },	/* sys_getpmsg */
[182] = {NOT_IMPLEMENTED, },	/* sys_putpmsg */
[183] = {NOT_IMPLEMENTED, },	/* sys_afs_syscall */
[184] = {NOT_IMPLEMENTED, },	/* sys_tuxcall */
[185] = {NOT_IMPLEMENTED, },	/* sys_security */
[186] = {0, },	/* sys_gettid */
[187] = { 3, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, } },	/* sys_readahead */
[188] = { 5, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, [4] = {VT, 4}, } },	/* sys_setxattr */
[189] = { 5, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, [4] = {VT, 4}, } },	/* sys_lsetxattr */
[190] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, [4] = {VT, 4}, } },	/* sys_fsetxattr */
[191] = { 4, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, } },	/* sys_getxattr */
[192] = { 4, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, } },	/* sys_lgetxattr */
[193] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, } },	/* sys_fgetxattr */
[194] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_listxattr */
[195] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_llistxattr */
[196] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_flistxattr */
[197] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_removexattr */
[198] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_lremovexattr */
[199] = { 2, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, } },	/* sys_fremovexattr */
[200] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_tkill */
[201] = { 1, { [0] = {PT, 8}, } },	/* sys_time */
[202] = { 6, { [0] = {PT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {PT, 16}, [4] = {PT, 4}, [5] = {VT, 4}} },	/* sys_futex */
[203] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 8}, } },	/* sys_sched_setaffinity */
[204] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 8}, } },	/* sys_sched_getaffinity */
[205] = { 1, { [0] = {PT, 16}, } },	/* sys_set_thread_area */
[206] = { 2, { [0] = {VT, 4}, [1] = {PT, 8}, } },	/* sys_io_setup */
[207] = { 1, { [0] = {VT, 8}, } },	/* sys_io_destroy */
[208] = { 5, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {AT, 32}, [4] = {PT, 16}, } },	/* sys_io_getevents */
[209] = { 3, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {MT, UNDEFINED_SIZE}, } },	/* sys_io_submit */
[210] = { 3, { [0] = {VT, 8}, [1] = {PT, 64}, [2] = {PT, 32}, } },	/* sys_io_cancel */
[211] = { 1, { [0] = {PT, 16}, } },	/* sys_get_thread_area */
[212] = { 3, { [0] = {VT, 8}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, } },	/* sys_lookup_dcookie */
[213] = { 1, { [0] = {VT, 4}, } },	/* sys_epoll_create */
[214] = {NOT_IMPLEMENTED, },	/* sys_epoll_ctl_old */
[215] = {NOT_IMPLEMENTED, },	/* sys_epoll_wait_old */
[216] = { 5, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_remap_file_pages */
[217] = { 3, { [0] = {VT, 4}, [1] = {AT, 24}, [2] = {VT, 4}, } },	/* sys_getdents64 */
[218] = { 1, { [0] = {PT, 4}, } },	/* sys_set_tid_address */
[219] = {0, },	/* sys_restart_syscall */
[220] = { 4, { [0] = {VT, 4}, [1] = {AT, 6}, [2] = {VT, 4}, [3] = {PT, 16}, } },	/* sys_semtimedop */
[221] = { 4, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_fadvise64 */
[222] = { 3, { [0] = {VT, 4}, [1] = {PT, 64}, [2] = {PT, 8}, } },	/* sys_timer_create */
[223] = { 4, { [0] = {VT, 8}, [1] = {VT, 4}, [2] = {PT, 32}, [3] = {PT, 32}, } },	/* sys_timer_settime */
[224] = { 2, { [0] = {VT, 8}, [1] = {PT, 32}, } },	/* sys_timer_gettime */
[225] = { 1, { [0] = {VT, 8}, } },	/* sys_timer_getoverrun */
[226] = { 1, { [0] = {VT, 8}, } },	/* sys_timer_delete */
[227] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_clock_settime */
[228] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_clock_gettime */
[229] = { 2, { [0] = {VT, 4}, [1] = {PT, 16}, } },	/* sys_clock_getres */
[230] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 16}, [3] = {PT, 16}, } },	/* sys_clock_nanosleep */
[231] = { 1, { [0] = {VT, 4}, } },	/* sys_exit_group */
[232] = { 4, { [0] = {VT, 4}, [1] = {AT, 12}, [2] = {VT, 4}, [3] = {VT, 4}, } },	/* sys_epoll_wait */
[233] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {PT, 12}, } },	/* sys_epoll_ctl */
[234] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_tgkill */
[235] = { 2, { [0] = {ST, UNDEFINED_SIZE}, [1] = {PT, 16}, } },	/* sys_utimes */
[236] = {NOT_IMPLEMENTED, },	/* sys_vserver */
[237] = { 6, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {AT, 8}, [4] = {VT, 8}, [5] = {VT, 4}} },	/* sys_mbind */
[238] = { 3, { [0] = {VT, 4}, [1] = {AT, 8}, [2] = {VT, 8}, } },	/* sys_set_mempolicy */
[239] = { 5, { [0] = {PT, 4}, [1] = {AT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_get_mempolicy */
[240] = { 4, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, [2] = {VT, 2}, [3] = {PT, 64}, } },	/* sys_mq_open */
[241] = { 1, { [0] = {ST, UNDEFINED_SIZE}, } },	/* sys_mq_unlink */
[242] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {VT, 4}, [4] = {PT, 16}, } },	/* sys_mq_timedsend */
[243] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 8}, [3] = {PT, 4}, [4] = {PT, 16}, } },	/* sys_mq_timedreceive */
[244] = { 2, { [0] = {VT, 4}, [1] = {PT, 64}, } },	/* sys_mq_notify */
[245] = { 3, { [0] = {VT, 4}, [1] = {PT, 64}, [2] = {PT, 64}, } },	/* sys_mq_getsetattr */
[246] = { 4, { [0] = {VT, 8}, [1] = {VT, 8}, [2] = {AT, 32}, [3] = {VT, 8}, } },	/* sys_kexec_load */
[247] = { 5, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 128}, [3] = {VT, 4}, [4] = {PT, 144}, } },	/* sys_waitid */
[248] = { 5, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, UNDEFINED_SIZE}, [3] = {VT, 8}, [4] = {VT, 4}, } },	/* sys_add_key */
[249] = { 4, { [0] = {ST, UNDEFINED_SIZE}, [1] = {ST, UNDEFINED_SIZE}, [2] = {ST, UNDEFINED_SIZE}, [3] = {VT, 4}, } },	/* sys_request_key */
[250] = { 5, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_keyctl */
[251] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_ioprio_set */
[252] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_ioprio_get */
[253] = {0, },	/* sys_inotify_init */
[254] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_inotify_add_watch */
[255] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_inotify_rm_watch */
[256] = { 4, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {AT, 8}, [3] = {AT, 8}, } },	/* sys_migrate_pages */
[257] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, [3] = {VT, 2}, } },	/* sys_openat */
[258] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 2}, } },	/* sys_mkdirat */
[259] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 2}, [3] = {VT, 4}, } },	/* sys_mknodat */
[260] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, [3] = {VT, 4}, [4] = {VT, 4}, } },	/* sys_fchownat */
[261] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {AT, 16}, } },	/* sys_futimesat */
[262] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, 144}, [3] = {VT, 4}, } },	/* sys_newfstatat */
[263] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_unlinkat */
[264] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, } },	/* sys_renameat */
[265] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, [3] = {ST, UNDEFINED_SIZE}, [4] = {VT, 4}, } },	/* sys_linkat */
[266] = { 3, { [0] = {ST, UNDEFINED_SIZE}, [1] = {VT, 4}, [2] = {ST, UNDEFINED_SIZE}, } },	/* sys_symlinkat */
[267] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {ST, UNDEFINED_SIZE}, [3] = {VT, 4}, } },	/* sys_readlinkat */
[268] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 2}, } },	/* sys_fchmodat */
[269] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_faccessat */
[270] = { 6, { [0] = {VT, 4}, [1] = {PT, 128}, [2] = {PT, 128}, [3] = {PT, 128}, [4] = {PT, 16}, [5] = {PT, 128}} },	/* sys_pselect6 */
[271] = { 5, { [0] = {AT, 8}, [1] = {VT, 4}, [2] = {PT, 16}, [3] = {PT, 128}, [4] = {VT, 8}, } },	/* sys_ppoll */
[272] = { 1, { [0] = {VT, 8}, } },	/* sys_unshare */
[273] = { 2, { [0] = {PT, 24}, [1] = {VT, 8}, } },	/* sys_set_robust_list */
[274] = { 3, { [0] = {VT, 4}, [1] = {PT, 8}, [2] = {PT, 8}, } },	/* sys_get_robust_list */
[275] = { 6, { [0] = {VT, 4}, [1] = {PT, 8}, [2] = {VT, 4}, [3] = {PT, 8}, [4] = {VT, 8}, [5] = {VT, 4}} },	/* sys_splice */
[276] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_tee */
[277] = { 4, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_sync_file_range */
[278] = { 4, { [0] = {VT, 4}, [1] = {AT, 16}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_vmsplice */
[279] = { 6, { [0] = {VT, 4}, [1] = {VT, 8}, [2] = {MT, UNDEFINED_SIZE}, [3] = {AT, 4}, [4] = {AT, 4}, [5] = {VT, 4}} },	/* sys_move_pages */
[280] = { 4, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, 16}, [3] = {VT, 4}, } },	/* sys_utimensat */
[281] = { 6, { [0] = {VT, 4}, [1] = {AT, 12}, [2] = {VT, 4}, [3] = {VT, 4}, [4] = {PT, 128}, [5] = {VT, 8}} },	/* sys_epoll_pwait */
[282] = { 3, { [0] = {VT, 4}, [1] = {PT, 128}, [2] = {VT, 8}, } },	/* sys_signalfd */
[283] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_timerfd_create */
[284] = { 1, { [0] = {VT, 4}, } },	/* sys_eventfd */
[285] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 8}, [3] = {VT, 8}, } },	/* sys_fallocate */
[286] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 32}, [3] = {PT, 32}, } },	/* sys_timerfd_settime */
[287] = { 2, { [0] = {VT, 4}, [1] = {PT, 32}, } },	/* sys_timerfd_gettime */
[288] = { 4, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {PT, 4}, [3] = {VT, 4}, } },	/* sys_accept4 */
[289] = { 4, { [0] = {VT, 4}, [1] = {PT, 128}, [2] = {VT, 8}, [3] = {VT, 4}, } },	/* sys_signalfd4 */
[290] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_eventfd2 */
[291] = { 1, { [0] = {VT, 4}, } },	/* sys_epoll_create1 */
[292] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, } },	/* sys_dup3 */
[293] = { 2, { [0] = {AT, 4}, [1] = {VT, 4}, } },	/* sys_pipe2 */
[294] = { 1, { [0] = {VT, 4}, } },	/* sys_inotify_init1 */
[295] = { 5, { [0] = {VT, 8}, [1] = {AT, 16}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_preadv */
[296] = { 5, { [0] = {VT, 8}, [1] = {AT, 16}, [2] = {VT, 8}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_pwritev */
[297] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {PT, 128}, } },	/* sys_rt_tgsigqueueinfo */
[298] = { 5, { [0] = {PT, 96}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {VT, 4}, [4] = {VT, 8}, } },	/* sys_perf_event_open */
[299] = { 5, { [0] = {VT, 4}, [1] = {AT, 64}, [2] = {VT, 4}, [3] = {VT, 4}, [4] = {PT, 16}, } },	/* sys_recvmmsg */
[300] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_fanotify_init */
[301] = { 5, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 8}, [3] = {VT, 4}, [4] = {ST, UNDEFINED_SIZE}, } },	/* sys_fanotify_mark */
[302] = { 4, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {PT, 16}, [3] = {PT, 16}, } },	/* sys_prlimit64 */
[303] = { 5, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {PT, 8}, [3] = {PT, 4}, [4] = {VT, 4}, } },	/* sys_name_to_handle_at */
[304] = { 3, { [0] = {VT, 4}, [1] = {PT, 8}, [2] = {VT, 4}, } },	/* sys_open_by_handle_at */
[305] = { 2, { [0] = {VT, 4}, [1] = {PT, 208}, } },	/* sys_clock_adjtime */
[306] = { 1, { [0] = {VT, 4}, } },	/* sys_syncfs */
[307] = { 4, { [0] = {VT, 4}, [1] = {AT, 64}, [2] = {VT, 4}, [3] = {VT, 4}, } },	/* sys_sendmmsg */
[308] = { 2, { [0] = {VT, 4}, [1] = {VT, 4}, } },	/* sys_setns */
[309] = { 3, { [0] = {PT, 4}, [1] = {PT, 4}, [2] = {PT, 128}, } },	/* sys_getcpu */
[310] = { 6, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 8}, [3] = {PT, 16}, [4] = {VT, 8}, [5] = {VT, 8}} },	/* sys_process_vm_readv */
[311] = { 6, { [0] = {VT, 4}, [1] = {PT, 16}, [2] = {VT, 8}, [3] = {PT, 16}, [4] = {VT, 8}, [5] = {VT, 8}} },	/* sys_process_vm_writev */
[312] = { 5, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {VT, 4}, [3] = {VT, 8}, [4] = {VT, 8}, } },	/* sys_kcmp */
[313] = { 3, { [0] = {VT, 4}, [1] = {ST, UNDEFINED_SIZE}, [2] = {VT, 4}, } },	/* sys_finit_module */
[314] = {NOT_IMPLEMENTED, },	/* sys_sched_setattr */
[315] = {NOT_IMPLEMENTED, },	/* sys_sched_getattr */
[316] = {NOT_IMPLEMENTED, },	/* sys_renameat2 */
[317] = { 3, { [0] = {VT, 4}, [1] = {VT, 4}, [2] = {ST, UNDEFINED_SIZE}, } },	/* sys_seccomp */
