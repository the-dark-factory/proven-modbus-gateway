/* config.h -- AUTHORED for the lovelace-mb Pi port (Linux variant of oracle/build/config.h; no autotools used).
 * Hand-written stand-in for the configure.ac checks of libmodbus a9b025d on Debian 12 bookworm, aarch64,
 * glibc 2.36, gcc 12.2.0 (Raspberry Pi 4). Differences from the macOS file, each checked on the Pi:
 *   HAVE_STRLCPY        NOT defined: glibc 2.36 has no strlcpy (2.38 adds it); libmodbus then uses its own copy.
 *   HAVE_ACCEPT4        1: Linux has accept4 (libmodbus uses it only to set SOCK_CLOEXEC on accepted sockets).
 *   HAVE_BYTESWAP_H     1: glibc ships <byteswap.h>.
 *   HAVE_LINUX_SERIAL_H 1, HAVE_DECL_TIOCSRS485 1: Linux kernel headers provide RS-485 ioctls (RTU only).
 *   HAVE_STRUCT_TERMIOS2 NOT defined (same as macOS): RTU-only; <asm/termbits.h> clashes with <termios.h>.
 *     The demo is TCP only, so RTU serial settings are never reached. */
#ifndef LOVELACE_MB_ORACLE_CONFIG_H
#define LOVELACE_MB_ORACLE_CONFIG_H
/* configure's AC_USE_SYSTEM_EXTENSIONS: needed on glibc for the accept4 prototype (gcc warned without it). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define HAVE_ARPA_INET_H 1
#define HAVE_ERRNO_H 1
#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 1
#define HAVE_NETDB_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_IP_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_TIME_H 1
#define HAVE_UNISTD_H 1
#define HAVE_BYTESWAP_H 1
#define HAVE_LINUX_SERIAL_H 1
#define HAVE_GAI_STRERROR 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_INET_PTON 1
#define HAVE_INET_NTOP 1
#define HAVE_SELECT 1
#define HAVE_SOCKET 1
#define HAVE_STRERROR 1
#define HAVE_ACCEPT4 1
#define HAVE_DECL___CYGWIN__ 0
#define HAVE_DECL_TIOCSRS485 1
#define HAVE_DECL_TIOCM_RTS 1
/* not defined: HAVE_STRLCPY, HAVE_STRUCT_TERMIOS2, HAVE_SYS_PARAMS_H */
#endif
