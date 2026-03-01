/*
 * busybox_stub.c – BusyBox multi-call binary (reconstructed stub)
 *
 * Original binary: /bin/busybox (652,492 bytes)
 * Firmware: EG8145V5-V500R022C00SPC340B019
 * Architecture: ARM32 Cortex-A9, musl libc, PIE ELF
 * Linker: /lib/ld-musl-arm.so.1
 *
 * BusyBox is a multi-call binary combining many Unix utilities.
 * The applet is selected based on argv[0] (symlink name).
 *
 * Dynamic library dependencies:
 *   - libc.so
 *
 * PLT imports:
 *   0x00004710  longjmp
 *   0x0000471c  stpcpy
 *   0x00004728  chroot
 *   0x00004734  strcpy
 *   0x00004740  unsetenv
 *   0x0000474c  setjmp
 *   0x00004758  waitpid
 *   0x00004764  getrlimit
 *   0x00004770  ioctl
 *   0x0000477c  getgid
 *   0x00004788  popen
 *   0x00004794  sysconf
 *   0x000047a0  printf
 *   0x000047ac  cfgetospeed
 *   0x000047b8  putc_unlocked
 *   0x000047c4  recv
 *   0x000047d0  connect
 *   0x000047dc  ungetc
 *   0x000047e8  tcgetsid
 *   0x000047f4  sigemptyset
 *   0x00004800  shmctl
 *   0x0000480c  strerror
 *   0x00004818  strndup
 *   0x00004824  geteuid
 *   0x00004830  inet_pton
 *   0x0000483c  memmove
 *   0x00004848  pclose
 *   0x00004854  getopt_long
 *   0x00004860  snprintf
 *   0x0000486c  syscall
 *   0x00004878  fileno_unlocked
 *   0x00004884  mknod
 *   0x00004890  getc_unlocked
 *   0x0000489c  __lstat_time64
 *   0x000048a8  getgrgid
 *   0x000048b4  times
 *   0x000048c0  getenv
 *   0x000048cc  __settimeofday_time64
 *   0x000048d8  fchmod
 *   0x000048e4  getegid
 *   0x000048f0  setpriority
 *   0x000048fc  getpriority
 *   0x00004908  bsearch
 *   0x00004914  usleep
 *   0x00004920  execve
 *   0x0000492c  __libc_current_sigrtmax
 *   0x00004938  semget
 *   0x00004944  getpagesize
 *   0x00004950  getpid
 *   0x0000495c  qsort
 *   0x00004968  fchown
 *   0x00004974  fscanf
 *   0x00004980  dirname
 *   0x0000498c  fchdir
 *   0x00004998  shmat
 *   0x000049a4  memcpy
 *   0x000049b0  __clock_settime64
 *   0x000049bc  execl
 *   0x000049c8  perror
 *   0x000049d4  readlink
 *   0x000049e0  puts
 *   0x000049ec  __cxa_finalize
 *   0x000049f8  dup2
 *   0x00004a04  __libc_current_sigrtmin
 *   0x00004a10  tcflush
 *   0x00004a1c  __select_time64
 *   0x00004a28  getuid
 *   0x00004a34  semctl
 *   0x00004a40  system
 *   0x00004a4c  hasmntopt
 *   0x00004a58  malloc
 *   0x00004a64  isatty
 *   0x00004a70  cfgetispeed
 *   0x00004a7c  endpwent
 *   0x00004a88  sleep
 *   0x00004a94  sysinfo
 *   0x00004aa0  strtoll
 *   0x00004aac  __localtime64
 *   0x00004ab8  vsnprintf
 *   0x00004ac4  recvfrom
 *   0x00004ad0  tcdrain
 *   0x00004adc  statfs
 *   0x00004ae8  strtoul
 *   0x00004af4  rmdir
 *   0x00004b00  socket
 *   0x00004b0c  readdir
 *   0x00004b18  lchown
 *   0x00004b24  setgroups
 *   0x00004b30  mempcpy
 *   0x00004b3c  fflush
 *   0x00004b48  ftruncate
 *   0x00004b54  realpath
 *   0x00004b60  putenv
 *   0x00004b6c  lseek
 *   0x00004b78  sigaddset
 *   0x00004b84  clearenv
 *   0x00004b90  chown
 *   0x00004b9c  strncasecmp
 *   0x00004ba8  setpgid
 *   0x00004bb4  send
 *   0x00004bc0  freeaddrinfo
 *   0x00004bcc  abort
 *   0x00004bd8  __stack_chk_fail
 *   0x00004be4  __gettimeofday_time64
 *   0x00004bf0  chmod
 *   0x00004bfc  getnameinfo
 *   0x00004c08  alarm
 *   0x00004c14  strtol
 *   0x00004c20  pipe
 *   0x00004c2c  getpgrp
 *   0x00004c38  strnlen
 *   0x00004c44  __sigtimedwait_time64
 *   0x00004c50  uname
 *   0x00004c5c  accept
 *   0x00004c68  cfsetispeed
 *   0x00004c74  rename
 *   0x00004c80  strrchr
 *   0x00004c8c  __nanosleep_time64
 *   0x00004c98  setrlimit
 *   0x00004ca4  __fstat_time64
 *   0x00004cb0  strtod
 *   0x00004cbc  write
 *   0x00004cc8  atof
 *   0x00004cd4  __ctime64
 *   0x00004ce0  fdatasync
 *   0x00004cec  fprintf
 *   0x00004cf8  kill
 *   0x00004d04  fputs_unlocked
 *   0x00004d10  setpwent
 *   0x00004d1c  dl_iterate_phdr
 *   0x00004d28  strcat
 *   0x00004d34  bind
 *   0x00004d40  getmntent_r
 *   0x00004d4c  __wait3_time64
 *   0x00004d58  ntohl
 *   0x00004d64  vprintf
 *   0x00004d70  umount2
 *   0x00004d7c  if_nametoindex
 *   0x00004d88  __deregister_frame_info
 *   0x00004d94  reboot
 *   0x00004da0  chdir
 *   0x00004dac  initgroups
 *   0x00004db8  fseeko
 *   0x00004dc4  __stat_time64
 *   0x00004dd0  shmdt
 *   0x00004ddc  endgrent
 *   0x00004de8  setsockopt
 *   0x00004df4  shmget
 *   0x00004e00  cfsetospeed
 *   0x00004e0c  memchr
 *   0x00004e18  swapoff
 *   0x00004e24  wait
 *   0x00004e30  umask
 *   0x00004e3c  dprintf
 *   0x00004e48  strcasestr
 *   0x00004e54  strstr
 *   0x00004e60  rand
 *   0x00004e6c  ftello
 *   0x00004e78  setgid
 *   0x00004e84  signal
 *   0x00004e90  read
 *   0x00004e9c  openlog
 *   0x00004ea8  sendmsg
 *   0x00004eb4  closelog
 *   0x00004ec0  strncmp
 *   0x00004ecc  sethostname
 *   0x00004ed8  setpgrp
 *   0x00004ee4  strncpy
 *   0x00004ef0  unlink
 *   0x00004efc  sync
 *   0x00004f08  setenv
 *   0x00004f14  strcasecmp
 *   0x00004f20  htonl
 *   0x00004f2c  sendto
 *   0x00004f38  realloc
 *   0x00004f44  strtok
 *   0x00004f50  sigfillset
 *   0x00004f5c  memcmp
 *   0x00004f68  listen
 *   0x00004f74  crypt
 *   0x00004f80  fdopen
 *   0x00004f8c  fork
 *   0x00004f98  sscanf
 *   0x00004fa4  setmntent
 *   0x00004fb0  statvfs
 *   0x00004fbc  setresuid
 *   0x00004fc8  execlp
 *   0x00004fd4  sigaction
 *   0x00004fe0  endmntent
 *   0x00004fec  killpg
 *   0x00004ff8  fread
 *   0x00005004  ttyname_r
 *   0x00005010  strdup
 *   0x0000501c  inet_aton
 *   0x00005028  strtoull
 *   0x00005034  regcomp
 *   0x00005040  symlink
 *   0x0000504c  fopen
 *   0x00005058  getopt
 *   0x00005064  memset
 *   0x00005070  fnmatch
 *   0x0000507c  cfmakeraw
 *   0x00005088  getsid
 *   0x00005094  srand
 *   0x000050a0  clearerr
 *   0x000050ac  fclose
 *   0x000050b8  ntohs
 *   0x000050c4  inet_ntoa
 *   0x000050d0  getppid
 *   0x000050dc  tcgetattr
 *   0x000050e8  getservbyport
 *   0x000050f4  regexec
 *   0x00005100  __localtime64_r
 *   0x0000510c  opendir
 *   0x00005118  getgroups
 *   0x00005124  __assert_fail
 *   0x00005130  msgctl
 *   0x0000513c  poll
 *   0x00005148  getgrouplist
 *   0x00005154  syslog
 *   0x00005160  seteuid
 *   0x0000516c  getopt_long_only
 *   0x00005178  mount
 *   0x00005184  strcmp
 *   0x00005190  shutdown
 *   0x0000519c  getpwuid
 *   0x000051a8  __h_errno_location
 *   0x000051b4  dup
 *   0x000051c0  swapon
 *   0x000051cc  getcwd
 *   0x000051d8  __time64
 *   0x000051e4  __gmtime64_r
 *   0x000051f0  gethostbyname
 *   0x000051fc  strsignal
 *   0x00005208  getpwnam
 *   0x00005214  getservbyname
 *   0x00005220  sprintf
 *   0x0000522c  strcspn
 *   0x00005238  getpeername
 *   0x00005244  cfsetspeed
 *   0x00005250  regerror
 *   0x0000525c  mkstemp
 *   0x00005268  vfork
 *   0x00005274  sched_getaffinity
 *   0x00005280  strsep
 *   0x0000528c  putchar_unlocked
 *   0x00005298  fsync
 *   0x000052a4  fputc
 *   0x000052b0  feof_unlocked
 *   0x000052bc  getchar_unlocked
 *   0x000052c8  sched_setaffinity
 *   0x000052d4  pread
 *   0x000052e0  getsockopt
 *   0x000052ec  hstrerror
 *   0x000052f8  getaddrinfo
 *   0x00005304  socketpair
 *   0x00005310  setresgid
 *   0x0000531c  strftime
 *   0x00005328  getmntent
 *   0x00005334  fwrite
 *   0x00005340  access
 *   0x0000534c  htons
 *   0x00005358  strptime
 *   0x00005364  freopen
 *   0x00005370  tcgetpgrp
 *   0x0000537c  __adjtimex_time64
 *   0x00005388  __errno_location
 *   0x00005394  link
 *   0x000053a0  semop
 *   0x000053ac  exit
 *   0x000053b8  klogctl
 *   0x000053c4  sigdelset
 *   0x000053d0  setbuf
 *   0x000053dc  inet_ntop
 *   0x000053e8  getgrnam
 *   0x000053f4  atoi
 *   0x00005400  ferror_unlocked
 *   0x0000540c  fgets_unlocked
 *   0x00005418  getline
 *   0x00005424  _exit
 *   0x00005430  strverscmp
 *   0x0000543c  getpwent
 *   0x00005448  strspn
 *   0x00005454  __mktime64
 *   0x00005460  __libc_start_main
 *   0x0000546c  strlen
 *   0x00005478  open
 *   0x00005484  atoll
 *   0x00005490  regfree
 *   0x0000549c  div
 *   0x000054a8  strchr
 *   0x000054b4  fputs
 *   0x000054c0  execvp
 *   0x000054cc  setsid
 *   0x000054d8  setegid
 *   0x000054e4  closedir
 *   0x000054f0  vasprintf
 *   0x000054fc  recvmsg
 *   0x00005508  strchrnul
 *   0x00005514  fcntl
 *   0x00005520  tzset
 *   0x0000552c  setuid
 *   0x00005538  tcsetattr
 *   0x00005544  mkdir
 *   0x00005550  __register_frame_info
 *   0x0000555c  msgget
 *   0x00005568  close
 *   0x00005574  vfprintf
 *   0x00005580  strpbrk
 *   0x0000558c  tcsetpgrp
 *   0x00005598  sigsuspend
 *   0x000055a4  raise
 *   0x000055b0  free
 *   0x000055bc  sigprocmask
 *   0x000055c8  __utimes_time64
 *   0x000055d4  getsockname
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── Applet dispatch table ─────────────────────────────────────── */

typedef int (*applet_main_t)(int argc, char **argv);

struct applet_entry {
    const char *name;
    applet_main_t main_fn;
};

static int async_main(int argc, char **argv);
static int atime_main(int argc, char **argv);
static int available_main(int argc, char **argv);
static int basename_main(int argc, char **argv);
static int bind_main(int argc, char **argv);
static int blkid_main(int argc, char **argv);
static int brctl_main(int argc, char **argv);
static int chmod_main(int argc, char **argv);
static int chown_main(int argc, char **argv);
static int chpasswd_main(int argc, char **argv);
static int chroot_main(int argc, char **argv);
static int clear_main(int argc, char **argv);
static int cols_main(int argc, char **argv);
static int columns_main(int argc, char **argv);
static int conv_main(int argc, char **argv);
static int crond_main(int argc, char **argv);
static int crontab_main(int argc, char **argv);
static int crterase_main(int argc, char **argv);
static int crtkill_main(int argc, char **argv);
static int ctlecho_main(int argc, char **argv);
static int date_main(int argc, char **argv);
static int delgroup_main(int argc, char **argv);
static int deluser_main(int argc, char **argv);
static int depmod_main(int argc, char **argv);
static int dhcprelay_main(int argc, char **argv);
static int diff_main(int argc, char **argv);
static int diratime_main(int argc, char **argv);
static int dirname_main(int argc, char **argv);
static int dirsync_main(int argc, char **argv);
static int dmesg_main(int argc, char **argv);
static int echo_main(int argc, char **argv);
static int echoctl_main(int argc, char **argv);
static int echoe_main(int argc, char **argv);
static int echok_main(int argc, char **argv);
static int echoke_main(int argc, char **argv);
static int echonl_main(int argc, char **argv);
static int echoprt_main(int argc, char **argv);
static int egrep_main(int argc, char **argv);
static int eject_main(int argc, char **argv);
static int expr_main(int argc, char **argv);
static int extproc_main(int argc, char **argv);
static int factor_main(int argc, char **argv);
static int false_main(int argc, char **argv);
static int fgrep_main(int argc, char **argv);
static int find_main(int argc, char **argv);
static int flush_main(int argc, char **argv);
static int flusho_main(int argc, char **argv);
static int free_main(int argc, char **argv);
static int fsync_main(int argc, char **argv);
static int ftpget_main(int argc, char **argv);
static int ftpput_main(int argc, char **argv);
static int fuser_main(int argc, char **argv);
static int getopt_main(int argc, char **argv);
static int getty_main(int argc, char **argv);
static int grep_main(int argc, char **argv);
static int gunzip_main(int argc, char **argv);
static int gzip_main(int argc, char **argv);
static int halt_main(int argc, char **argv);
static int head_main(int argc, char **argv);
static int hexdump_main(int argc, char **argv);
static int hostname_main(int argc, char **argv);
static int hours_main(int argc, char **argv);
static int hwclock_main(int argc, char **argv);
static int ifconfig_main(int argc, char **argv);
static int iflag_main(int argc, char **argv);
static int inet_main(int argc, char **argv);
static int init_main(int argc, char **argv);
static int insmod_main(int argc, char **argv);
static int ipaddr_main(int argc, char **argv);
static int ipcrm_main(int argc, char **argv);
static int ipcs_main(int argc, char **argv);
static int iplink_main(int argc, char **argv);
static int iproute_main(int argc, char **argv);
static int iprule_main(int argc, char **argv);
static int iptunnel_main(int argc, char **argv);
static int ispeed_main(int argc, char **argv);
static int kill_main(int argc, char **argv);
static int killall_main(int argc, char **argv);
static int klogd_main(int argc, char **argv);
static int line_main(int argc, char **argv);
static int link_main(int argc, char **argv);
static int linuxrc_main(int argc, char **argv);
static int logger_main(int argc, char **argv);
static int logread_main(int argc, char **argv);
static int losetup_main(int argc, char **argv);
static int loud_main(int argc, char **argv);
static int lsmod_main(int argc, char **argv);
static int lspci_main(int argc, char **argv);
static int lsusb_main(int argc, char **argv);
static int lzcat_main(int argc, char **argv);
static int lzma_main(int argc, char **argv);
static int make_private_main(int argc, char **argv);
static int make_rprivate_main(int argc, char **argv);
static int make_rshared_main(int argc, char **argv);
static int make_rslave_main(int argc, char **argv);
static int make_runbindable_main(int argc, char **argv);
static int make_shared_main(int argc, char **argv);
static int make_slave_main(int argc, char **argv);
static int make_unbindable_main(int argc, char **argv);
static int makedevs_main(int argc, char **argv);
static int mand_main(int argc, char **argv);
static int md5sum_main(int argc, char **argv);
static int mdev_main(int argc, char **argv);
static int minutes_main(int argc, char **argv);
static int mkdir_main(int argc, char **argv);
static int mknod_main(int argc, char **argv);
static int mkswap_main(int argc, char **argv);
static int modprobe_main(int argc, char **argv);
static int more_main(int argc, char **argv);
static int mount_main(int argc, char **argv);
static int mountpoint_main(int argc, char **argv);
static int move_main(int argc, char **argv);
static int neigh_main(int argc, char **argv);
static int netstat_main(int argc, char **argv);
static int nice_main(int argc, char **argv);
static int noatime_main(int argc, char **argv);
static int nodiratime_main(int argc, char **argv);
static int noerror_main(int argc, char **argv);
static int noflsh_main(int argc, char **argv);
static int nologin_main(int argc, char **argv);
static int nomand_main(int argc, char **argv);
static int norelatime_main(int argc, char **argv);
static int notrunc_main(int argc, char **argv);
static int nproc_main(int argc, char **argv);
static int ntable_main(int argc, char **argv);
static int ntpd_main(int argc, char **argv);
static int oflag_main(int argc, char **argv);
static int ospeed_main(int argc, char **argv);
static int paste_main(int argc, char **argv);
static int pidof_main(int argc, char **argv);
static int poweroff_main(int argc, char **argv);
static int printenv_main(int argc, char **argv);
static int printf_main(int argc, char **argv);
static int prterase_main(int argc, char **argv);
static int rbind_main(int argc, char **argv);
static int readlink_main(int argc, char **argv);
static int realpath_main(int argc, char **argv);
static int reboot_main(int argc, char **argv);
static int relatime_main(int argc, char **argv);
static int remount_main(int argc, char **argv);
static int renice_main(int argc, char **argv);
static int resume_main(int argc, char **argv);
static int rmdir_main(int argc, char **argv);
static int rmmod_main(int argc, char **argv);
static int route_main(int argc, char **argv);
static int rows_main(int argc, char **argv);
static int rule_main(int argc, char **argv);
static int seconds_main(int argc, char **argv);
static int setconsole_main(int argc, char **argv);
static int shred_main(int argc, char **argv);
static int size_main(int argc, char **argv);
static int sleep_main(int argc, char **argv);
static int sort_main(int argc, char **argv);
static int speed_main(int argc, char **argv);
static int start_stop_daemon_main(int argc, char **argv);
static int stat_main(int argc, char **argv);
static int strictatime_main(int argc, char **argv);
static int strings_main(int argc, char **argv);
static int stty_main(int argc, char **argv);
static int swab_main(int argc, char **argv);
static int swapoff_main(int argc, char **argv);
static int swapon_main(int argc, char **argv);
static int sync_main(int argc, char **argv);
static int sysctl_main(int argc, char **argv);
static int syslogd_main(int argc, char **argv);
static int tail_main(int argc, char **argv);
static int taskset_main(int argc, char **argv);
static int telnet_main(int argc, char **argv);
static int test_main(int argc, char **argv);
static int tftp_main(int argc, char **argv);
static int tftpd_main(int argc, char **argv);
static int time_main(int argc, char **argv);
static int tostop_main(int argc, char **argv);
static int total_main(int argc, char **argv);
static int touch_main(int argc, char **argv);
static int true_main(int argc, char **argv);
static int tunl_main(int argc, char **argv);
static int tunnel_main(int argc, char **argv);
static int udpsvd_main(int argc, char **argv);
static int umount_main(int argc, char **argv);
static int uname_main(int argc, char **argv);
static int union_main(int argc, char **argv);
static int uniq_main(int argc, char **argv);
static int unlzma_main(int argc, char **argv);
static int unzip_main(int argc, char **argv);
static int uptime_main(int argc, char **argv);
static int usleep_main(int argc, char **argv);
static int vconfig_main(int argc, char **argv);
static int wget_main(int argc, char **argv);
static int which_main(int argc, char **argv);
static int whoami_main(int argc, char **argv);
static int xargs_main(int argc, char **argv);
static int xcase_main(int argc, char **argv);
static int zcat_main(int argc, char **argv);

static const struct applet_entry applet_table[] = {
    { "async", async_main },
    { "atime", atime_main },
    { "available", available_main },
    { "basename", basename_main },
    { "bind", bind_main },
    { "blkid", blkid_main },
    { "brctl", brctl_main },
    { "chmod", chmod_main },
    { "chown", chown_main },
    { "chpasswd", chpasswd_main },
    { "chroot", chroot_main },
    { "clear", clear_main },
    { "cols", cols_main },
    { "columns", columns_main },
    { "conv", conv_main },
    { "crond", crond_main },
    { "crontab", crontab_main },
    { "crterase", crterase_main },
    { "crtkill", crtkill_main },
    { "ctlecho", ctlecho_main },
    { "date", date_main },
    { "delgroup", delgroup_main },
    { "deluser", deluser_main },
    { "depmod", depmod_main },
    { "dhcprelay", dhcprelay_main },
    { "diff", diff_main },
    { "diratime", diratime_main },
    { "dirname", dirname_main },
    { "dirsync", dirsync_main },
    { "dmesg", dmesg_main },
    { "echo", echo_main },
    { "echoctl", echoctl_main },
    { "echoe", echoe_main },
    { "echok", echok_main },
    { "echoke", echoke_main },
    { "echonl", echonl_main },
    { "echoprt", echoprt_main },
    { "egrep", egrep_main },
    { "eject", eject_main },
    { "expr", expr_main },
    { "extproc", extproc_main },
    { "factor", factor_main },
    { "false", false_main },
    { "fgrep", fgrep_main },
    { "find", find_main },
    { "flush", flush_main },
    { "flusho", flusho_main },
    { "free", free_main },
    { "fsync", fsync_main },
    { "ftpget", ftpget_main },
    { "ftpput", ftpput_main },
    { "fuser", fuser_main },
    { "getopt", getopt_main },
    { "getty", getty_main },
    { "grep", grep_main },
    { "gunzip", gunzip_main },
    { "gzip", gzip_main },
    { "halt", halt_main },
    { "head", head_main },
    { "hexdump", hexdump_main },
    { "hostname", hostname_main },
    { "hours", hours_main },
    { "hwclock", hwclock_main },
    { "ifconfig", ifconfig_main },
    { "iflag", iflag_main },
    { "inet", inet_main },
    { "init", init_main },
    { "insmod", insmod_main },
    { "ipaddr", ipaddr_main },
    { "ipcrm", ipcrm_main },
    { "ipcs", ipcs_main },
    { "iplink", iplink_main },
    { "iproute", iproute_main },
    { "iprule", iprule_main },
    { "iptunnel", iptunnel_main },
    { "ispeed", ispeed_main },
    { "kill", kill_main },
    { "killall", killall_main },
    { "klogd", klogd_main },
    { "line", line_main },
    { "link", link_main },
    { "linuxrc", linuxrc_main },
    { "logger", logger_main },
    { "logread", logread_main },
    { "losetup", losetup_main },
    { "loud", loud_main },
    { "lsmod", lsmod_main },
    { "lspci", lspci_main },
    { "lsusb", lsusb_main },
    { "lzcat", lzcat_main },
    { "lzma", lzma_main },
    { "make-private", make_private_main },
    { "make-rprivate", make_rprivate_main },
    { "make-rshared", make_rshared_main },
    { "make-rslave", make_rslave_main },
    { "make-runbindable", make_runbindable_main },
    { "make-shared", make_shared_main },
    { "make-slave", make_slave_main },
    { "make-unbindable", make_unbindable_main },
    { "makedevs", makedevs_main },
    { "mand", mand_main },
    { "md5sum", md5sum_main },
    { "mdev", mdev_main },
    { "minutes", minutes_main },
    { "mkdir", mkdir_main },
    { "mknod", mknod_main },
    { "mkswap", mkswap_main },
    { "modprobe", modprobe_main },
    { "more", more_main },
    { "mount", mount_main },
    { "mountpoint", mountpoint_main },
    { "move", move_main },
    { "neigh", neigh_main },
    { "netstat", netstat_main },
    { "nice", nice_main },
    { "noatime", noatime_main },
    { "nodiratime", nodiratime_main },
    { "noerror", noerror_main },
    { "noflsh", noflsh_main },
    { "nologin", nologin_main },
    { "nomand", nomand_main },
    { "norelatime", norelatime_main },
    { "notrunc", notrunc_main },
    { "nproc", nproc_main },
    { "ntable", ntable_main },
    { "ntpd", ntpd_main },
    { "oflag", oflag_main },
    { "ospeed", ospeed_main },
    { "paste", paste_main },
    { "pidof", pidof_main },
    { "poweroff", poweroff_main },
    { "printenv", printenv_main },
    { "printf", printf_main },
    { "prterase", prterase_main },
    { "rbind", rbind_main },
    { "readlink", readlink_main },
    { "realpath", realpath_main },
    { "reboot", reboot_main },
    { "relatime", relatime_main },
    { "remount", remount_main },
    { "renice", renice_main },
    { "resume", resume_main },
    { "rmdir", rmdir_main },
    { "rmmod", rmmod_main },
    { "route", route_main },
    { "rows", rows_main },
    { "rule", rule_main },
    { "seconds", seconds_main },
    { "setconsole", setconsole_main },
    { "shred", shred_main },
    { "size", size_main },
    { "sleep", sleep_main },
    { "sort", sort_main },
    { "speed", speed_main },
    { "start-stop-daemon", start_stop_daemon_main },
    { "stat", stat_main },
    { "strictatime", strictatime_main },
    { "strings", strings_main },
    { "stty", stty_main },
    { "swab", swab_main },
    { "swapoff", swapoff_main },
    { "swapon", swapon_main },
    { "sync", sync_main },
    { "sysctl", sysctl_main },
    { "syslogd", syslogd_main },
    { "tail", tail_main },
    { "taskset", taskset_main },
    { "telnet", telnet_main },
    { "test", test_main },
    { "tftp", tftp_main },
    { "tftpd", tftpd_main },
    { "time", time_main },
    { "tostop", tostop_main },
    { "total", total_main },
    { "touch", touch_main },
    { "true", true_main },
    { "tunl", tunl_main },
    { "tunnel", tunnel_main },
    { "udpsvd", udpsvd_main },
    { "umount", umount_main },
    { "uname", uname_main },
    { "union", union_main },
    { "uniq", uniq_main },
    { "unlzma", unlzma_main },
    { "unzip", unzip_main },
    { "uptime", uptime_main },
    { "usleep", usleep_main },
    { "vconfig", vconfig_main },
    { "wget", wget_main },
    { "which", which_main },
    { "whoami", whoami_main },
    { "xargs", xargs_main },
    { "xcase", xcase_main },
    { "zcat", zcat_main },
    { NULL, NULL }
};

/* ── Main entry point ──────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *applet = strrchr(argv[0], '/');
    applet = applet ? applet + 1 : argv[0];

    if (strcmp(applet, "busybox") == 0 && argc > 1) {
        applet = argv[1];
        argv++;
        argc--;
    }

    for (const struct applet_entry *e = applet_table; e->name; e++) {
        if (strcmp(applet, e->name) == 0)
            return e->main_fn(argc, argv);
    }

    fprintf(stderr, "busybox: applet not found: %s\n", applet);
    return 127;
}

/* ── Applet stubs (implementations elided) ───────────────────── */

static int async_main(int argc, char **argv)
{
    /* TODO: async implementation */
    (void)argc; (void)argv;
    return 0;
}

static int atime_main(int argc, char **argv)
{
    /* TODO: atime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int available_main(int argc, char **argv)
{
    /* TODO: available implementation */
    (void)argc; (void)argv;
    return 0;
}

static int basename_main(int argc, char **argv)
{
    /* TODO: basename implementation */
    (void)argc; (void)argv;
    return 0;
}

static int bind_main(int argc, char **argv)
{
    /* TODO: bind implementation */
    (void)argc; (void)argv;
    return 0;
}

static int blkid_main(int argc, char **argv)
{
    /* TODO: blkid implementation */
    (void)argc; (void)argv;
    return 0;
}

static int brctl_main(int argc, char **argv)
{
    /* TODO: brctl implementation */
    (void)argc; (void)argv;
    return 0;
}

static int chmod_main(int argc, char **argv)
{
    /* TODO: chmod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int chown_main(int argc, char **argv)
{
    /* TODO: chown implementation */
    (void)argc; (void)argv;
    return 0;
}

static int chpasswd_main(int argc, char **argv)
{
    /* TODO: chpasswd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int chroot_main(int argc, char **argv)
{
    /* TODO: chroot implementation */
    (void)argc; (void)argv;
    return 0;
}

static int clear_main(int argc, char **argv)
{
    /* TODO: clear implementation */
    (void)argc; (void)argv;
    return 0;
}

static int cols_main(int argc, char **argv)
{
    /* TODO: cols implementation */
    (void)argc; (void)argv;
    return 0;
}

static int columns_main(int argc, char **argv)
{
    /* TODO: columns implementation */
    (void)argc; (void)argv;
    return 0;
}

static int conv_main(int argc, char **argv)
{
    /* TODO: conv implementation */
    (void)argc; (void)argv;
    return 0;
}

static int crond_main(int argc, char **argv)
{
    /* TODO: crond implementation */
    (void)argc; (void)argv;
    return 0;
}

static int crontab_main(int argc, char **argv)
{
    /* TODO: crontab implementation */
    (void)argc; (void)argv;
    return 0;
}

static int crterase_main(int argc, char **argv)
{
    /* TODO: crterase implementation */
    (void)argc; (void)argv;
    return 0;
}

static int crtkill_main(int argc, char **argv)
{
    /* TODO: crtkill implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ctlecho_main(int argc, char **argv)
{
    /* TODO: ctlecho implementation */
    (void)argc; (void)argv;
    return 0;
}

static int date_main(int argc, char **argv)
{
    /* TODO: date implementation */
    (void)argc; (void)argv;
    return 0;
}

static int delgroup_main(int argc, char **argv)
{
    /* TODO: delgroup implementation */
    (void)argc; (void)argv;
    return 0;
}

static int deluser_main(int argc, char **argv)
{
    /* TODO: deluser implementation */
    (void)argc; (void)argv;
    return 0;
}

static int depmod_main(int argc, char **argv)
{
    /* TODO: depmod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int dhcprelay_main(int argc, char **argv)
{
    /* TODO: dhcprelay implementation */
    (void)argc; (void)argv;
    return 0;
}

static int diff_main(int argc, char **argv)
{
    /* TODO: diff implementation */
    (void)argc; (void)argv;
    return 0;
}

static int diratime_main(int argc, char **argv)
{
    /* TODO: diratime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int dirname_main(int argc, char **argv)
{
    /* TODO: dirname implementation */
    (void)argc; (void)argv;
    return 0;
}

static int dirsync_main(int argc, char **argv)
{
    /* TODO: dirsync implementation */
    (void)argc; (void)argv;
    return 0;
}

static int dmesg_main(int argc, char **argv)
{
    /* TODO: dmesg implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echo_main(int argc, char **argv)
{
    /* TODO: echo implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echoctl_main(int argc, char **argv)
{
    /* TODO: echoctl implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echoe_main(int argc, char **argv)
{
    /* TODO: echoe implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echok_main(int argc, char **argv)
{
    /* TODO: echok implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echoke_main(int argc, char **argv)
{
    /* TODO: echoke implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echonl_main(int argc, char **argv)
{
    /* TODO: echonl implementation */
    (void)argc; (void)argv;
    return 0;
}

static int echoprt_main(int argc, char **argv)
{
    /* TODO: echoprt implementation */
    (void)argc; (void)argv;
    return 0;
}

static int egrep_main(int argc, char **argv)
{
    /* TODO: egrep implementation */
    (void)argc; (void)argv;
    return 0;
}

static int eject_main(int argc, char **argv)
{
    /* TODO: eject implementation */
    (void)argc; (void)argv;
    return 0;
}

static int expr_main(int argc, char **argv)
{
    /* TODO: expr implementation */
    (void)argc; (void)argv;
    return 0;
}

static int extproc_main(int argc, char **argv)
{
    /* TODO: extproc implementation */
    (void)argc; (void)argv;
    return 0;
}

static int factor_main(int argc, char **argv)
{
    /* TODO: factor implementation */
    (void)argc; (void)argv;
    return 0;
}

static int false_main(int argc, char **argv)
{
    /* TODO: false implementation */
    (void)argc; (void)argv;
    return 0;
}

static int fgrep_main(int argc, char **argv)
{
    /* TODO: fgrep implementation */
    (void)argc; (void)argv;
    return 0;
}

static int find_main(int argc, char **argv)
{
    /* TODO: find implementation */
    (void)argc; (void)argv;
    return 0;
}

static int flush_main(int argc, char **argv)
{
    /* TODO: flush implementation */
    (void)argc; (void)argv;
    return 0;
}

static int flusho_main(int argc, char **argv)
{
    /* TODO: flusho implementation */
    (void)argc; (void)argv;
    return 0;
}

static int free_main(int argc, char **argv)
{
    /* TODO: free implementation */
    (void)argc; (void)argv;
    return 0;
}

static int fsync_main(int argc, char **argv)
{
    /* TODO: fsync implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ftpget_main(int argc, char **argv)
{
    /* TODO: ftpget implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ftpput_main(int argc, char **argv)
{
    /* TODO: ftpput implementation */
    (void)argc; (void)argv;
    return 0;
}

static int fuser_main(int argc, char **argv)
{
    /* TODO: fuser implementation */
    (void)argc; (void)argv;
    return 0;
}

static int getopt_main(int argc, char **argv)
{
    /* TODO: getopt implementation */
    (void)argc; (void)argv;
    return 0;
}

static int getty_main(int argc, char **argv)
{
    /* TODO: getty implementation */
    (void)argc; (void)argv;
    return 0;
}

static int grep_main(int argc, char **argv)
{
    /* TODO: grep implementation */
    (void)argc; (void)argv;
    return 0;
}

static int gunzip_main(int argc, char **argv)
{
    /* TODO: gunzip implementation */
    (void)argc; (void)argv;
    return 0;
}

static int gzip_main(int argc, char **argv)
{
    /* TODO: gzip implementation */
    (void)argc; (void)argv;
    return 0;
}

static int halt_main(int argc, char **argv)
{
    /* TODO: halt implementation */
    (void)argc; (void)argv;
    return 0;
}

static int head_main(int argc, char **argv)
{
    /* TODO: head implementation */
    (void)argc; (void)argv;
    return 0;
}

static int hexdump_main(int argc, char **argv)
{
    /* TODO: hexdump implementation */
    (void)argc; (void)argv;
    return 0;
}

static int hostname_main(int argc, char **argv)
{
    /* TODO: hostname implementation */
    (void)argc; (void)argv;
    return 0;
}

static int hours_main(int argc, char **argv)
{
    /* TODO: hours implementation */
    (void)argc; (void)argv;
    return 0;
}

static int hwclock_main(int argc, char **argv)
{
    /* TODO: hwclock implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ifconfig_main(int argc, char **argv)
{
    /* TODO: ifconfig implementation */
    (void)argc; (void)argv;
    return 0;
}

static int iflag_main(int argc, char **argv)
{
    /* TODO: iflag implementation */
    (void)argc; (void)argv;
    return 0;
}

static int inet_main(int argc, char **argv)
{
    /* TODO: inet implementation */
    (void)argc; (void)argv;
    return 0;
}

static int init_main(int argc, char **argv)
{
    /* TODO: init implementation */
    (void)argc; (void)argv;
    return 0;
}

static int insmod_main(int argc, char **argv)
{
    /* TODO: insmod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ipaddr_main(int argc, char **argv)
{
    /* TODO: ipaddr implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ipcrm_main(int argc, char **argv)
{
    /* TODO: ipcrm implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ipcs_main(int argc, char **argv)
{
    /* TODO: ipcs implementation */
    (void)argc; (void)argv;
    return 0;
}

static int iplink_main(int argc, char **argv)
{
    /* TODO: iplink implementation */
    (void)argc; (void)argv;
    return 0;
}

static int iproute_main(int argc, char **argv)
{
    /* TODO: iproute implementation */
    (void)argc; (void)argv;
    return 0;
}

static int iprule_main(int argc, char **argv)
{
    /* TODO: iprule implementation */
    (void)argc; (void)argv;
    return 0;
}

static int iptunnel_main(int argc, char **argv)
{
    /* TODO: iptunnel implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ispeed_main(int argc, char **argv)
{
    /* TODO: ispeed implementation */
    (void)argc; (void)argv;
    return 0;
}

static int kill_main(int argc, char **argv)
{
    /* TODO: kill implementation */
    (void)argc; (void)argv;
    return 0;
}

static int killall_main(int argc, char **argv)
{
    /* TODO: killall implementation */
    (void)argc; (void)argv;
    return 0;
}

static int klogd_main(int argc, char **argv)
{
    /* TODO: klogd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int line_main(int argc, char **argv)
{
    /* TODO: line implementation */
    (void)argc; (void)argv;
    return 0;
}

static int link_main(int argc, char **argv)
{
    /* TODO: link implementation */
    (void)argc; (void)argv;
    return 0;
}

static int linuxrc_main(int argc, char **argv)
{
    /* TODO: linuxrc implementation */
    (void)argc; (void)argv;
    return 0;
}

static int logger_main(int argc, char **argv)
{
    /* TODO: logger implementation */
    (void)argc; (void)argv;
    return 0;
}

static int logread_main(int argc, char **argv)
{
    /* TODO: logread implementation */
    (void)argc; (void)argv;
    return 0;
}

static int losetup_main(int argc, char **argv)
{
    /* TODO: losetup implementation */
    (void)argc; (void)argv;
    return 0;
}

static int loud_main(int argc, char **argv)
{
    /* TODO: loud implementation */
    (void)argc; (void)argv;
    return 0;
}

static int lsmod_main(int argc, char **argv)
{
    /* TODO: lsmod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int lspci_main(int argc, char **argv)
{
    /* TODO: lspci implementation */
    (void)argc; (void)argv;
    return 0;
}

static int lsusb_main(int argc, char **argv)
{
    /* TODO: lsusb implementation */
    (void)argc; (void)argv;
    return 0;
}

static int lzcat_main(int argc, char **argv)
{
    /* TODO: lzcat implementation */
    (void)argc; (void)argv;
    return 0;
}

static int lzma_main(int argc, char **argv)
{
    /* TODO: lzma implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_private_main(int argc, char **argv)
{
    /* TODO: make-private implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_rprivate_main(int argc, char **argv)
{
    /* TODO: make-rprivate implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_rshared_main(int argc, char **argv)
{
    /* TODO: make-rshared implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_rslave_main(int argc, char **argv)
{
    /* TODO: make-rslave implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_runbindable_main(int argc, char **argv)
{
    /* TODO: make-runbindable implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_shared_main(int argc, char **argv)
{
    /* TODO: make-shared implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_slave_main(int argc, char **argv)
{
    /* TODO: make-slave implementation */
    (void)argc; (void)argv;
    return 0;
}

static int make_unbindable_main(int argc, char **argv)
{
    /* TODO: make-unbindable implementation */
    (void)argc; (void)argv;
    return 0;
}

static int makedevs_main(int argc, char **argv)
{
    /* TODO: makedevs implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mand_main(int argc, char **argv)
{
    /* TODO: mand implementation */
    (void)argc; (void)argv;
    return 0;
}

static int md5sum_main(int argc, char **argv)
{
    /* TODO: md5sum implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mdev_main(int argc, char **argv)
{
    /* TODO: mdev implementation */
    (void)argc; (void)argv;
    return 0;
}

static int minutes_main(int argc, char **argv)
{
    /* TODO: minutes implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mkdir_main(int argc, char **argv)
{
    /* TODO: mkdir implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mknod_main(int argc, char **argv)
{
    /* TODO: mknod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mkswap_main(int argc, char **argv)
{
    /* TODO: mkswap implementation */
    (void)argc; (void)argv;
    return 0;
}

static int modprobe_main(int argc, char **argv)
{
    /* TODO: modprobe implementation */
    (void)argc; (void)argv;
    return 0;
}

static int more_main(int argc, char **argv)
{
    /* TODO: more implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mount_main(int argc, char **argv)
{
    /* TODO: mount implementation */
    (void)argc; (void)argv;
    return 0;
}

static int mountpoint_main(int argc, char **argv)
{
    /* TODO: mountpoint implementation */
    (void)argc; (void)argv;
    return 0;
}

static int move_main(int argc, char **argv)
{
    /* TODO: move implementation */
    (void)argc; (void)argv;
    return 0;
}

static int neigh_main(int argc, char **argv)
{
    /* TODO: neigh implementation */
    (void)argc; (void)argv;
    return 0;
}

static int netstat_main(int argc, char **argv)
{
    /* TODO: netstat implementation */
    (void)argc; (void)argv;
    return 0;
}

static int nice_main(int argc, char **argv)
{
    /* TODO: nice implementation */
    (void)argc; (void)argv;
    return 0;
}

static int noatime_main(int argc, char **argv)
{
    /* TODO: noatime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int nodiratime_main(int argc, char **argv)
{
    /* TODO: nodiratime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int noerror_main(int argc, char **argv)
{
    /* TODO: noerror implementation */
    (void)argc; (void)argv;
    return 0;
}

static int noflsh_main(int argc, char **argv)
{
    /* TODO: noflsh implementation */
    (void)argc; (void)argv;
    return 0;
}

static int nologin_main(int argc, char **argv)
{
    /* TODO: nologin implementation */
    (void)argc; (void)argv;
    return 0;
}

static int nomand_main(int argc, char **argv)
{
    /* TODO: nomand implementation */
    (void)argc; (void)argv;
    return 0;
}

static int norelatime_main(int argc, char **argv)
{
    /* TODO: norelatime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int notrunc_main(int argc, char **argv)
{
    /* TODO: notrunc implementation */
    (void)argc; (void)argv;
    return 0;
}

static int nproc_main(int argc, char **argv)
{
    /* TODO: nproc implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ntable_main(int argc, char **argv)
{
    /* TODO: ntable implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ntpd_main(int argc, char **argv)
{
    /* TODO: ntpd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int oflag_main(int argc, char **argv)
{
    /* TODO: oflag implementation */
    (void)argc; (void)argv;
    return 0;
}

static int ospeed_main(int argc, char **argv)
{
    /* TODO: ospeed implementation */
    (void)argc; (void)argv;
    return 0;
}

static int paste_main(int argc, char **argv)
{
    /* TODO: paste implementation */
    (void)argc; (void)argv;
    return 0;
}

static int pidof_main(int argc, char **argv)
{
    /* TODO: pidof implementation */
    (void)argc; (void)argv;
    return 0;
}

static int poweroff_main(int argc, char **argv)
{
    /* TODO: poweroff implementation */
    (void)argc; (void)argv;
    return 0;
}

static int printenv_main(int argc, char **argv)
{
    /* TODO: printenv implementation */
    (void)argc; (void)argv;
    return 0;
}

static int printf_main(int argc, char **argv)
{
    /* TODO: printf implementation */
    (void)argc; (void)argv;
    return 0;
}

static int prterase_main(int argc, char **argv)
{
    /* TODO: prterase implementation */
    (void)argc; (void)argv;
    return 0;
}

static int rbind_main(int argc, char **argv)
{
    /* TODO: rbind implementation */
    (void)argc; (void)argv;
    return 0;
}

static int readlink_main(int argc, char **argv)
{
    /* TODO: readlink implementation */
    (void)argc; (void)argv;
    return 0;
}

static int realpath_main(int argc, char **argv)
{
    /* TODO: realpath implementation */
    (void)argc; (void)argv;
    return 0;
}

static int reboot_main(int argc, char **argv)
{
    /* TODO: reboot implementation */
    (void)argc; (void)argv;
    return 0;
}

static int relatime_main(int argc, char **argv)
{
    /* TODO: relatime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int remount_main(int argc, char **argv)
{
    /* TODO: remount implementation */
    (void)argc; (void)argv;
    return 0;
}

static int renice_main(int argc, char **argv)
{
    /* TODO: renice implementation */
    (void)argc; (void)argv;
    return 0;
}

static int resume_main(int argc, char **argv)
{
    /* TODO: resume implementation */
    (void)argc; (void)argv;
    return 0;
}

static int rmdir_main(int argc, char **argv)
{
    /* TODO: rmdir implementation */
    (void)argc; (void)argv;
    return 0;
}

static int rmmod_main(int argc, char **argv)
{
    /* TODO: rmmod implementation */
    (void)argc; (void)argv;
    return 0;
}

static int route_main(int argc, char **argv)
{
    /* TODO: route implementation */
    (void)argc; (void)argv;
    return 0;
}

static int rows_main(int argc, char **argv)
{
    /* TODO: rows implementation */
    (void)argc; (void)argv;
    return 0;
}

static int rule_main(int argc, char **argv)
{
    /* TODO: rule implementation */
    (void)argc; (void)argv;
    return 0;
}

static int seconds_main(int argc, char **argv)
{
    /* TODO: seconds implementation */
    (void)argc; (void)argv;
    return 0;
}

static int setconsole_main(int argc, char **argv)
{
    /* TODO: setconsole implementation */
    (void)argc; (void)argv;
    return 0;
}

static int shred_main(int argc, char **argv)
{
    /* TODO: shred implementation */
    (void)argc; (void)argv;
    return 0;
}

static int size_main(int argc, char **argv)
{
    /* TODO: size implementation */
    (void)argc; (void)argv;
    return 0;
}

static int sleep_main(int argc, char **argv)
{
    /* TODO: sleep implementation */
    (void)argc; (void)argv;
    return 0;
}

static int sort_main(int argc, char **argv)
{
    /* TODO: sort implementation */
    (void)argc; (void)argv;
    return 0;
}

static int speed_main(int argc, char **argv)
{
    /* TODO: speed implementation */
    (void)argc; (void)argv;
    return 0;
}

static int start_stop_daemon_main(int argc, char **argv)
{
    /* TODO: start-stop-daemon implementation */
    (void)argc; (void)argv;
    return 0;
}

static int stat_main(int argc, char **argv)
{
    /* TODO: stat implementation */
    (void)argc; (void)argv;
    return 0;
}

static int strictatime_main(int argc, char **argv)
{
    /* TODO: strictatime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int strings_main(int argc, char **argv)
{
    /* TODO: strings implementation */
    (void)argc; (void)argv;
    return 0;
}

static int stty_main(int argc, char **argv)
{
    /* TODO: stty implementation */
    (void)argc; (void)argv;
    return 0;
}

static int swab_main(int argc, char **argv)
{
    /* TODO: swab implementation */
    (void)argc; (void)argv;
    return 0;
}

static int swapoff_main(int argc, char **argv)
{
    /* TODO: swapoff implementation */
    (void)argc; (void)argv;
    return 0;
}

static int swapon_main(int argc, char **argv)
{
    /* TODO: swapon implementation */
    (void)argc; (void)argv;
    return 0;
}

static int sync_main(int argc, char **argv)
{
    /* TODO: sync implementation */
    (void)argc; (void)argv;
    return 0;
}

static int sysctl_main(int argc, char **argv)
{
    /* TODO: sysctl implementation */
    (void)argc; (void)argv;
    return 0;
}

static int syslogd_main(int argc, char **argv)
{
    /* TODO: syslogd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tail_main(int argc, char **argv)
{
    /* TODO: tail implementation */
    (void)argc; (void)argv;
    return 0;
}

static int taskset_main(int argc, char **argv)
{
    /* TODO: taskset implementation */
    (void)argc; (void)argv;
    return 0;
}

static int telnet_main(int argc, char **argv)
{
    /* TODO: telnet implementation */
    (void)argc; (void)argv;
    return 0;
}

static int test_main(int argc, char **argv)
{
    /* TODO: test implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tftp_main(int argc, char **argv)
{
    /* TODO: tftp implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tftpd_main(int argc, char **argv)
{
    /* TODO: tftpd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int time_main(int argc, char **argv)
{
    /* TODO: time implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tostop_main(int argc, char **argv)
{
    /* TODO: tostop implementation */
    (void)argc; (void)argv;
    return 0;
}

static int total_main(int argc, char **argv)
{
    /* TODO: total implementation */
    (void)argc; (void)argv;
    return 0;
}

static int touch_main(int argc, char **argv)
{
    /* TODO: touch implementation */
    (void)argc; (void)argv;
    return 0;
}

static int true_main(int argc, char **argv)
{
    /* TODO: true implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tunl_main(int argc, char **argv)
{
    /* TODO: tunl implementation */
    (void)argc; (void)argv;
    return 0;
}

static int tunnel_main(int argc, char **argv)
{
    /* TODO: tunnel implementation */
    (void)argc; (void)argv;
    return 0;
}

static int udpsvd_main(int argc, char **argv)
{
    /* TODO: udpsvd implementation */
    (void)argc; (void)argv;
    return 0;
}

static int umount_main(int argc, char **argv)
{
    /* TODO: umount implementation */
    (void)argc; (void)argv;
    return 0;
}

static int uname_main(int argc, char **argv)
{
    /* TODO: uname implementation */
    (void)argc; (void)argv;
    return 0;
}

static int union_main(int argc, char **argv)
{
    /* TODO: union implementation */
    (void)argc; (void)argv;
    return 0;
}

static int uniq_main(int argc, char **argv)
{
    /* TODO: uniq implementation */
    (void)argc; (void)argv;
    return 0;
}

static int unlzma_main(int argc, char **argv)
{
    /* TODO: unlzma implementation */
    (void)argc; (void)argv;
    return 0;
}

static int unzip_main(int argc, char **argv)
{
    /* TODO: unzip implementation */
    (void)argc; (void)argv;
    return 0;
}

static int uptime_main(int argc, char **argv)
{
    /* TODO: uptime implementation */
    (void)argc; (void)argv;
    return 0;
}

static int usleep_main(int argc, char **argv)
{
    /* TODO: usleep implementation */
    (void)argc; (void)argv;
    return 0;
}

static int vconfig_main(int argc, char **argv)
{
    /* TODO: vconfig implementation */
    (void)argc; (void)argv;
    return 0;
}

static int wget_main(int argc, char **argv)
{
    /* TODO: wget implementation */
    (void)argc; (void)argv;
    return 0;
}

static int which_main(int argc, char **argv)
{
    /* TODO: which implementation */
    (void)argc; (void)argv;
    return 0;
}

static int whoami_main(int argc, char **argv)
{
    /* TODO: whoami implementation */
    (void)argc; (void)argv;
    return 0;
}

static int xargs_main(int argc, char **argv)
{
    /* TODO: xargs implementation */
    (void)argc; (void)argv;
    return 0;
}

static int xcase_main(int argc, char **argv)
{
    /* TODO: xcase implementation */
    (void)argc; (void)argv;
    return 0;
}

static int zcat_main(int argc, char **argv)
{
    /* TODO: zcat implementation */
    (void)argc; (void)argv;
    return 0;
}

