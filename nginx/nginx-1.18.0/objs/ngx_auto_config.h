#define NGX_CONFIGURE " --prefix=/etc/nginx --conf-path=/etc/nginx/nginx.conf --user=nginx --group=nginx --sbin-path=/usr/sbin/nginx --with-zlib=/root/src/zlib-1.2.11 --with-http_stub_status_module --with-http_realip_module --with-openssl=/root/src/openssl-1.0.2t --with-http_geoip_module --with-http_v2_module --without-http_memcached_module --with-http_ssl_module --with-http_gzip_static_module --with-http_perl_module --with-pcre --with-http_secure_link_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module --without-http_split_clients_module --without-http_empty_gif_module --without-http_browser_module --without-http_userid_module --add-module=/root/src/incubator-pagespeed-ngx-latest-stable --add-module=/root/src/nginx-module-vts --add-module=/root/src/ngx_cache_purge --add-module=/root/src/testcookie-nginx-module --add-module=/root/src/headers-more-nginx-module"

#ifndef NGX_COMPILER
#define NGX_COMPILER  "gcc 4.8.5 20150623 (Red Hat 4.8.5-39) (GCC) "
#endif


#ifndef NGX_HAVE_GCC_ATOMIC
#define NGX_HAVE_GCC_ATOMIC  1
#endif


#ifndef NGX_HAVE_C99_VARIADIC_MACROS
#define NGX_HAVE_C99_VARIADIC_MACROS  1
#endif


#ifndef NGX_HAVE_GCC_VARIADIC_MACROS
#define NGX_HAVE_GCC_VARIADIC_MACROS  1
#endif


#ifndef NGX_HAVE_GCC_BSWAP64
#define NGX_HAVE_GCC_BSWAP64  1
#endif


#ifndef NGX_HAVE_EPOLL
#define NGX_HAVE_EPOLL  1
#endif


#ifndef NGX_HAVE_CLEAR_EVENT
#define NGX_HAVE_CLEAR_EVENT  1
#endif


#ifndef NGX_HAVE_EPOLLRDHUP
#define NGX_HAVE_EPOLLRDHUP  1
#endif


#ifndef NGX_HAVE_O_PATH
#define NGX_HAVE_O_PATH  1
#endif


#ifndef NGX_HAVE_SENDFILE
#define NGX_HAVE_SENDFILE  1
#endif


#ifndef NGX_HAVE_SENDFILE64
#define NGX_HAVE_SENDFILE64  1
#endif


#ifndef NGX_HAVE_PR_SET_DUMPABLE
#define NGX_HAVE_PR_SET_DUMPABLE  1
#endif


#ifndef NGX_HAVE_PR_SET_KEEPCAPS
#define NGX_HAVE_PR_SET_KEEPCAPS  1
#endif


#ifndef NGX_HAVE_CAPABILITIES
#define NGX_HAVE_CAPABILITIES  1
#endif


#ifndef NGX_HAVE_GNU_CRYPT_R
#define NGX_HAVE_GNU_CRYPT_R  1
#endif


#ifndef NGX_HAVE_NONALIGNED
#define NGX_HAVE_NONALIGNED  1
#endif


#ifndef NGX_CPU_CACHE_LINE
#define NGX_CPU_CACHE_LINE  64
#endif


#define NGX_KQUEUE_UDATA_T  (void *)


#ifndef NGX_HAVE_POSIX_FADVISE
#define NGX_HAVE_POSIX_FADVISE  1
#endif


#ifndef NGX_HAVE_O_DIRECT
#define NGX_HAVE_O_DIRECT  1
#endif


#ifndef NGX_HAVE_ALIGNED_DIRECTIO
#define NGX_HAVE_ALIGNED_DIRECTIO  1
#endif


#ifndef NGX_HAVE_STATFS
#define NGX_HAVE_STATFS  1
#endif


#ifndef NGX_HAVE_STATVFS
#define NGX_HAVE_STATVFS  1
#endif


#ifndef NGX_HAVE_DLOPEN
#define NGX_HAVE_DLOPEN  1
#endif


#ifndef NGX_HAVE_SCHED_YIELD
#define NGX_HAVE_SCHED_YIELD  1
#endif


#ifndef NGX_HAVE_SCHED_SETAFFINITY
#define NGX_HAVE_SCHED_SETAFFINITY  1
#endif


#ifndef NGX_HAVE_REUSEPORT
#define NGX_HAVE_REUSEPORT  1
#endif


#ifndef NGX_HAVE_TRANSPARENT_PROXY
#define NGX_HAVE_TRANSPARENT_PROXY  1
#endif


#ifndef NGX_HAVE_IP_PKTINFO
#define NGX_HAVE_IP_PKTINFO  1
#endif


#ifndef NGX_HAVE_IPV6_RECVPKTINFO
#define NGX_HAVE_IPV6_RECVPKTINFO  1
#endif


#ifndef NGX_HAVE_DEFERRED_ACCEPT
#define NGX_HAVE_DEFERRED_ACCEPT  1
#endif


#ifndef NGX_HAVE_KEEPALIVE_TUNABLE
#define NGX_HAVE_KEEPALIVE_TUNABLE  1
#endif


#ifndef NGX_HAVE_TCP_FASTOPEN
#define NGX_HAVE_TCP_FASTOPEN  1
#endif


#ifndef NGX_HAVE_TCP_INFO
#define NGX_HAVE_TCP_INFO  1
#endif


#ifndef NGX_HAVE_ACCEPT4
#define NGX_HAVE_ACCEPT4  1
#endif


#ifndef NGX_HAVE_EVENTFD
#define NGX_HAVE_EVENTFD  1
#endif


#ifndef NGX_HAVE_SYS_EVENTFD_H
#define NGX_HAVE_SYS_EVENTFD_H  1
#endif


#ifndef NGX_HAVE_UNIX_DOMAIN
#define NGX_HAVE_UNIX_DOMAIN  1
#endif


#ifndef NGX_PTR_SIZE
#define NGX_PTR_SIZE  8
#endif


#ifndef NGX_SIG_ATOMIC_T_SIZE
#define NGX_SIG_ATOMIC_T_SIZE  4
#endif


#ifndef NGX_HAVE_LITTLE_ENDIAN
#define NGX_HAVE_LITTLE_ENDIAN  1
#endif

