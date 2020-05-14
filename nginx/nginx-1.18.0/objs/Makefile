
CC =	cc
CFLAGS =  -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g   -D_GLIBCXX_USE_CXX11_ABI=0 -Wno-unused-local-typedefs -Wno-error
CPP =	cc -E
LINK =	$(CC)

NGX_PERL_CFLAGS = -pipe -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -D_GLIBCXX_USE_CXX11_ABI=0 -Wno-unused-local-typedefs -Wno-error -D_REENTRANT -D_GNU_SOURCE -fno-strict-aliasing -pipe -fstack-protector -I/usr/local/include -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I/usr/lib64/perl5/CORE
NGX_PM_CFLAGS = -D_REENTRANT -D_GNU_SOURCE -fno-strict-aliasing -pipe -fstack-protector -I/usr/local/include -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -I/usr/lib64/perl5/CORE
NGX_PM_LDFLAGS = -shared -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -Wl,-z,relro

ALL_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/os/unix \
	-I /root/src/openssl-1.0.2k/.openssl/include \
	-I /root/src/zlib-1.2.11 \
	-I objs \
	-I src/http \
	-I src/http/modules \
	-I src/http/v2 \
	-I src/http/modules/perl \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/chromium/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/src/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/grpc/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/protobuf/src/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/re2/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen/protoc_out/instaweb \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/url


CORE_DEPS = src/core/nginx.h \
	src/core/ngx_config.h \
	src/core/ngx_core.h \
	src/core/ngx_log.h \
	src/core/ngx_palloc.h \
	src/core/ngx_array.h \
	src/core/ngx_list.h \
	src/core/ngx_hash.h \
	src/core/ngx_buf.h \
	src/core/ngx_queue.h \
	src/core/ngx_string.h \
	src/core/ngx_parse.h \
	src/core/ngx_parse_time.h \
	src/core/ngx_inet.h \
	src/core/ngx_file.h \
	src/core/ngx_crc.h \
	src/core/ngx_crc32.h \
	src/core/ngx_murmurhash.h \
	src/core/ngx_md5.h \
	src/core/ngx_sha1.h \
	src/core/ngx_rbtree.h \
	src/core/ngx_radix_tree.h \
	src/core/ngx_rwlock.h \
	src/core/ngx_slab.h \
	src/core/ngx_times.h \
	src/core/ngx_shmtx.h \
	src/core/ngx_connection.h \
	src/core/ngx_cycle.h \
	src/core/ngx_conf_file.h \
	src/core/ngx_module.h \
	src/core/ngx_resolver.h \
	src/core/ngx_open_file_cache.h \
	src/core/ngx_crypt.h \
	src/core/ngx_proxy_protocol.h \
	src/core/ngx_syslog.h \
	src/event/ngx_event.h \
	src/event/ngx_event_timer.h \
	src/event/ngx_event_posted.h \
	src/event/ngx_event_connect.h \
	src/event/ngx_event_pipe.h \
	src/os/unix/ngx_time.h \
	src/os/unix/ngx_errno.h \
	src/os/unix/ngx_alloc.h \
	src/os/unix/ngx_files.h \
	src/os/unix/ngx_channel.h \
	src/os/unix/ngx_shmem.h \
	src/os/unix/ngx_process.h \
	src/os/unix/ngx_setaffinity.h \
	src/os/unix/ngx_setproctitle.h \
	src/os/unix/ngx_atomic.h \
	src/os/unix/ngx_gcc_atomic_x86.h \
	src/os/unix/ngx_thread.h \
	src/os/unix/ngx_socket.h \
	src/os/unix/ngx_os.h \
	src/os/unix/ngx_user.h \
	src/os/unix/ngx_dlopen.h \
	src/os/unix/ngx_process_cycle.h \
	src/os/unix/ngx_linux_config.h \
	src/os/unix/ngx_linux.h \
	src/event/ngx_event_openssl.h \
	src/core/ngx_regex.h \
	/root/src/openssl-1.0.2k/.openssl/include/openssl/ssl.h \
	objs/ngx_auto_config.h


CORE_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/os/unix \
	-I /root/src/openssl-1.0.2k/.openssl/include \
	-I /root/src/zlib-1.2.11 \
	-I objs


HTTP_DEPS = src/http/ngx_http.h \
	src/http/ngx_http_request.h \
	src/http/ngx_http_config.h \
	src/http/ngx_http_core_module.h \
	src/http/ngx_http_cache.h \
	src/http/ngx_http_variables.h \
	src/http/ngx_http_script.h \
	src/http/ngx_http_upstream.h \
	src/http/ngx_http_upstream_round_robin.h \
	src/http/modules/ngx_http_ssi_filter_module.h \
	src/http/v2/ngx_http_v2.h \
	src/http/v2/ngx_http_v2_module.h \
	src/http/modules/ngx_http_ssl_module.h \
	src/http/modules/perl/ngx_http_perl_module.h


HTTP_INCS = -I src/http \
	-I src/http/modules \
	-I src/http/v2 \
	-I src/http/modules/perl \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/chromium/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/src/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/grpc/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/protobuf/src/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/re2/src \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen/protoc_out/instaweb \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/src/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/gen/arch/linux/x64/include \
	-I /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/url


ADDON_DEPS = $(CORE_DEPS)  /root/src/incubator-pagespeed-ngx-latest-stable/src/log_message_handler.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_base_fetch.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_caching_headers.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_event_connection.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_fetch.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_gzip_setter.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_list_iterator.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_message_handler.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_pagespeed.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_driver_factory.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_options.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_server_context.h /root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_url_async_fetcher.h /root/src/incubator-pagespeed-ngx-latest-stable/psol/lib/Release/linux/x64/pagespeed_automatic.a                   /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_module.h                              /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_variables.h                           /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_string.h                              /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_shm.h                                 /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_node.h                                /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_filter.h                              /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_control.h                             /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_limit.h                               /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display.h                             /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_json.h                        /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_prometheus.h                  /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_set.h                                 /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_dump.h                                /root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_module_html.h                                                                                                   /root/src/headers-more-nginx-module/src/ddebug.h                                                 /root/src/headers-more-nginx-module/src/ngx_http_headers_more_filter_module.h                    /root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_in.h                       /root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_out.h                      /root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_in.h                       /root/src/headers-more-nginx-module/src/ngx_http_headers_more_util.h                              $(HTTP_DEPS)


build:	binary modules manpage

binary:	objs/nginx

objs/nginx:	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_parse_time.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_sha1.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_rwlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_module.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/core/ngx_proxy_protocol.o \
	objs/src/core/ngx_syslog.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_udp.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_udp_send.o \
	objs/src/os/unix/ngx_udp_sendmsg_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_dlopen.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/event/ngx_event_openssl_stapling.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/v2/ngx_http_v2_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/ngx_http_postpone_filter_module.o \
	objs/src/http/modules/ngx_http_ssi_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/v2/ngx_http_v2.o \
	objs/src/http/v2/ngx_http_v2_table.o \
	objs/src/http/v2/ngx_http_v2_encode.o \
	objs/src/http/v2/ngx_http_v2_huff_decode.o \
	objs/src/http/v2/ngx_http_v2_huff_encode.o \
	objs/src/http/v2/ngx_http_v2_module.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_gzip_static_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_mirror_module.o \
	objs/src/http/modules/ngx_http_try_files_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_realip_module.o \
	objs/src/http/modules/ngx_http_geo_module.o \
	objs/src/http/modules/ngx_http_geoip_module.o \
	objs/src/http/modules/ngx_http_map_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_ssl_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_uwsgi_module.o \
	objs/src/http/modules/ngx_http_scgi_module.o \
	objs/src/http/modules/ngx_http_grpc_module.o \
	objs/src/http/modules/perl/ngx_http_perl_module.o \
	objs/src/http/modules/ngx_http_secure_link_module.o \
	objs/src/http/modules/ngx_http_upstream_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_random_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_upstream_zone_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/addon/src/log_message_handler.o \
	objs/addon/src/ngx_base_fetch.o \
	objs/addon/src/ngx_caching_headers.o \
	objs/addon/src/ngx_event_connection.o \
	objs/addon/src/ngx_fetch.o \
	objs/addon/src/ngx_gzip_setter.o \
	objs/addon/src/ngx_list_iterator.o \
	objs/addon/src/ngx_message_handler.o \
	objs/addon/src/ngx_pagespeed.o \
	objs/addon/src/ngx_rewrite_driver_factory.o \
	objs/addon/src/ngx_rewrite_options.o \
	objs/addon/src/ngx_server_context.o \
	objs/addon/src/ngx_url_async_fetcher.o \
	objs/addon/src/ngx_http_vhost_traffic_status_module.o \
	objs/addon/src/ngx_http_vhost_traffic_status_variables.o \
	objs/addon/src/ngx_http_vhost_traffic_status_string.o \
	objs/addon/src/ngx_http_vhost_traffic_status_shm.o \
	objs/addon/src/ngx_http_vhost_traffic_status_node.o \
	objs/addon/src/ngx_http_vhost_traffic_status_filter.o \
	objs/addon/src/ngx_http_vhost_traffic_status_control.o \
	objs/addon/src/ngx_http_vhost_traffic_status_limit.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display_json.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display_prometheus.o \
	objs/addon/src/ngx_http_vhost_traffic_status_set.o \
	objs/addon/src/ngx_http_vhost_traffic_status_dump.o \
	objs/addon/ngx_cache_purge/ngx_cache_purge_module.o \
	objs/addon/src/ngx_http_testcookie_access_module.o \
	objs/addon/src/ngx_http_headers_more_filter_module.o \
	objs/addon/src/ngx_http_headers_more_headers_out.o \
	objs/addon/src/ngx_http_headers_more_headers_in.o \
	objs/addon/src/ngx_http_headers_more_util.o \
	objs/ngx_modules.o \
	/root/src/zlib-1.2.11/libz.a

	$(LINK) -o objs/nginx \
	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_parse_time.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_sha1.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_rwlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_module.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/core/ngx_proxy_protocol.o \
	objs/src/core/ngx_syslog.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_udp.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_udp_send.o \
	objs/src/os/unix/ngx_udp_sendmsg_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_dlopen.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/event/ngx_event_openssl_stapling.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/v2/ngx_http_v2_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/ngx_http_postpone_filter_module.o \
	objs/src/http/modules/ngx_http_ssi_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/v2/ngx_http_v2.o \
	objs/src/http/v2/ngx_http_v2_table.o \
	objs/src/http/v2/ngx_http_v2_encode.o \
	objs/src/http/v2/ngx_http_v2_huff_decode.o \
	objs/src/http/v2/ngx_http_v2_huff_encode.o \
	objs/src/http/v2/ngx_http_v2_module.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_gzip_static_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_mirror_module.o \
	objs/src/http/modules/ngx_http_try_files_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_realip_module.o \
	objs/src/http/modules/ngx_http_geo_module.o \
	objs/src/http/modules/ngx_http_geoip_module.o \
	objs/src/http/modules/ngx_http_map_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_ssl_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_uwsgi_module.o \
	objs/src/http/modules/ngx_http_scgi_module.o \
	objs/src/http/modules/ngx_http_grpc_module.o \
	objs/src/http/modules/perl/ngx_http_perl_module.o \
	objs/src/http/modules/ngx_http_secure_link_module.o \
	objs/src/http/modules/ngx_http_upstream_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_random_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_upstream_zone_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/addon/src/log_message_handler.o \
	objs/addon/src/ngx_base_fetch.o \
	objs/addon/src/ngx_caching_headers.o \
	objs/addon/src/ngx_event_connection.o \
	objs/addon/src/ngx_fetch.o \
	objs/addon/src/ngx_gzip_setter.o \
	objs/addon/src/ngx_list_iterator.o \
	objs/addon/src/ngx_message_handler.o \
	objs/addon/src/ngx_pagespeed.o \
	objs/addon/src/ngx_rewrite_driver_factory.o \
	objs/addon/src/ngx_rewrite_options.o \
	objs/addon/src/ngx_server_context.o \
	objs/addon/src/ngx_url_async_fetcher.o \
	objs/addon/src/ngx_http_vhost_traffic_status_module.o \
	objs/addon/src/ngx_http_vhost_traffic_status_variables.o \
	objs/addon/src/ngx_http_vhost_traffic_status_string.o \
	objs/addon/src/ngx_http_vhost_traffic_status_shm.o \
	objs/addon/src/ngx_http_vhost_traffic_status_node.o \
	objs/addon/src/ngx_http_vhost_traffic_status_filter.o \
	objs/addon/src/ngx_http_vhost_traffic_status_control.o \
	objs/addon/src/ngx_http_vhost_traffic_status_limit.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display_json.o \
	objs/addon/src/ngx_http_vhost_traffic_status_display_prometheus.o \
	objs/addon/src/ngx_http_vhost_traffic_status_set.o \
	objs/addon/src/ngx_http_vhost_traffic_status_dump.o \
	objs/addon/ngx_cache_purge/ngx_cache_purge_module.o \
	objs/addon/src/ngx_http_testcookie_access_module.o \
	objs/addon/src/ngx_http_headers_more_filter_module.o \
	objs/addon/src/ngx_http_headers_more_headers_out.o \
	objs/addon/src/ngx_http_headers_more_headers_in.o \
	objs/addon/src/ngx_http_headers_more_util.o \
	objs/ngx_modules.o \
	-ldl -lpthread -lcrypt /root/src/incubator-pagespeed-ngx-latest-stable/psol/lib/Release/linux/x64/pagespeed_automatic.a -lstdc++ -lrt -pthread -lm -luuid -lpcre /root/src/openssl-1.0.2k/.openssl/lib/libssl.a /root/src/openssl-1.0.2k/.openssl/lib/libcrypto.a -ldl -lpthread /root/src/zlib-1.2.11/libz.a -lGeoIP \
	-Wl,--enable-new-dtags -Wl,-rpath,/usr/lib64/perl5/CORE -fstack-protector -L/usr/lib64/perl5/CORE -lperl -lresolv -lnsl -ldl -lm -lcrypt -lutil -lpthread -lc \
	-Wl,-E
	


modules:

objs/ngx_modules.o:	$(CORE_DEPS) \
	objs/ngx_modules.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/ngx_modules.o \
		objs/ngx_modules.c


objs/src/core/nginx.o:	$(CORE_DEPS) \
	src/core/nginx.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/nginx.o \
		src/core/nginx.c


objs/src/core/ngx_log.o:	$(CORE_DEPS) \
	src/core/ngx_log.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_log.o \
		src/core/ngx_log.c


objs/src/core/ngx_palloc.o:	$(CORE_DEPS) \
	src/core/ngx_palloc.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_palloc.o \
		src/core/ngx_palloc.c


objs/src/core/ngx_array.o:	$(CORE_DEPS) \
	src/core/ngx_array.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_array.o \
		src/core/ngx_array.c


objs/src/core/ngx_list.o:	$(CORE_DEPS) \
	src/core/ngx_list.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_list.o \
		src/core/ngx_list.c


objs/src/core/ngx_hash.o:	$(CORE_DEPS) \
	src/core/ngx_hash.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_hash.o \
		src/core/ngx_hash.c


objs/src/core/ngx_buf.o:	$(CORE_DEPS) \
	src/core/ngx_buf.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_buf.o \
		src/core/ngx_buf.c


objs/src/core/ngx_queue.o:	$(CORE_DEPS) \
	src/core/ngx_queue.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_queue.o \
		src/core/ngx_queue.c


objs/src/core/ngx_output_chain.o:	$(CORE_DEPS) \
	src/core/ngx_output_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_output_chain.o \
		src/core/ngx_output_chain.c


objs/src/core/ngx_string.o:	$(CORE_DEPS) \
	src/core/ngx_string.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_string.o \
		src/core/ngx_string.c


objs/src/core/ngx_parse.o:	$(CORE_DEPS) \
	src/core/ngx_parse.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_parse.o \
		src/core/ngx_parse.c


objs/src/core/ngx_parse_time.o:	$(CORE_DEPS) \
	src/core/ngx_parse_time.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_parse_time.o \
		src/core/ngx_parse_time.c


objs/src/core/ngx_inet.o:	$(CORE_DEPS) \
	src/core/ngx_inet.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_inet.o \
		src/core/ngx_inet.c


objs/src/core/ngx_file.o:	$(CORE_DEPS) \
	src/core/ngx_file.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_file.o \
		src/core/ngx_file.c


objs/src/core/ngx_crc32.o:	$(CORE_DEPS) \
	src/core/ngx_crc32.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crc32.o \
		src/core/ngx_crc32.c


objs/src/core/ngx_murmurhash.o:	$(CORE_DEPS) \
	src/core/ngx_murmurhash.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_murmurhash.o \
		src/core/ngx_murmurhash.c


objs/src/core/ngx_md5.o:	$(CORE_DEPS) \
	src/core/ngx_md5.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_md5.o \
		src/core/ngx_md5.c


objs/src/core/ngx_sha1.o:	$(CORE_DEPS) \
	src/core/ngx_sha1.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_sha1.o \
		src/core/ngx_sha1.c


objs/src/core/ngx_rbtree.o:	$(CORE_DEPS) \
	src/core/ngx_rbtree.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_rbtree.o \
		src/core/ngx_rbtree.c


objs/src/core/ngx_radix_tree.o:	$(CORE_DEPS) \
	src/core/ngx_radix_tree.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_radix_tree.o \
		src/core/ngx_radix_tree.c


objs/src/core/ngx_slab.o:	$(CORE_DEPS) \
	src/core/ngx_slab.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_slab.o \
		src/core/ngx_slab.c


objs/src/core/ngx_times.o:	$(CORE_DEPS) \
	src/core/ngx_times.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_times.o \
		src/core/ngx_times.c


objs/src/core/ngx_shmtx.o:	$(CORE_DEPS) \
	src/core/ngx_shmtx.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_shmtx.o \
		src/core/ngx_shmtx.c


objs/src/core/ngx_connection.o:	$(CORE_DEPS) \
	src/core/ngx_connection.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_connection.o \
		src/core/ngx_connection.c


objs/src/core/ngx_cycle.o:	$(CORE_DEPS) \
	src/core/ngx_cycle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cycle.o \
		src/core/ngx_cycle.c


objs/src/core/ngx_spinlock.o:	$(CORE_DEPS) \
	src/core/ngx_spinlock.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_spinlock.o \
		src/core/ngx_spinlock.c


objs/src/core/ngx_rwlock.o:	$(CORE_DEPS) \
	src/core/ngx_rwlock.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_rwlock.o \
		src/core/ngx_rwlock.c


objs/src/core/ngx_cpuinfo.o:	$(CORE_DEPS) \
	src/core/ngx_cpuinfo.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cpuinfo.o \
		src/core/ngx_cpuinfo.c


objs/src/core/ngx_conf_file.o:	$(CORE_DEPS) \
	src/core/ngx_conf_file.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_conf_file.o \
		src/core/ngx_conf_file.c


objs/src/core/ngx_module.o:	$(CORE_DEPS) \
	src/core/ngx_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_module.o \
		src/core/ngx_module.c


objs/src/core/ngx_resolver.o:	$(CORE_DEPS) \
	src/core/ngx_resolver.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_resolver.o \
		src/core/ngx_resolver.c


objs/src/core/ngx_open_file_cache.o:	$(CORE_DEPS) \
	src/core/ngx_open_file_cache.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_open_file_cache.o \
		src/core/ngx_open_file_cache.c


objs/src/core/ngx_crypt.o:	$(CORE_DEPS) \
	src/core/ngx_crypt.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crypt.o \
		src/core/ngx_crypt.c


objs/src/core/ngx_proxy_protocol.o:	$(CORE_DEPS) \
	src/core/ngx_proxy_protocol.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_proxy_protocol.o \
		src/core/ngx_proxy_protocol.c


objs/src/core/ngx_syslog.o:	$(CORE_DEPS) \
	src/core/ngx_syslog.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_syslog.o \
		src/core/ngx_syslog.c


objs/src/event/ngx_event.o:	$(CORE_DEPS) \
	src/event/ngx_event.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event.o \
		src/event/ngx_event.c


objs/src/event/ngx_event_timer.o:	$(CORE_DEPS) \
	src/event/ngx_event_timer.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_timer.o \
		src/event/ngx_event_timer.c


objs/src/event/ngx_event_posted.o:	$(CORE_DEPS) \
	src/event/ngx_event_posted.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_posted.o \
		src/event/ngx_event_posted.c


objs/src/event/ngx_event_accept.o:	$(CORE_DEPS) \
	src/event/ngx_event_accept.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_accept.o \
		src/event/ngx_event_accept.c


objs/src/event/ngx_event_udp.o:	$(CORE_DEPS) \
	src/event/ngx_event_udp.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_udp.o \
		src/event/ngx_event_udp.c


objs/src/event/ngx_event_connect.o:	$(CORE_DEPS) \
	src/event/ngx_event_connect.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_connect.o \
		src/event/ngx_event_connect.c


objs/src/event/ngx_event_pipe.o:	$(CORE_DEPS) \
	src/event/ngx_event_pipe.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_pipe.o \
		src/event/ngx_event_pipe.c


objs/src/os/unix/ngx_time.o:	$(CORE_DEPS) \
	src/os/unix/ngx_time.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_time.o \
		src/os/unix/ngx_time.c


objs/src/os/unix/ngx_errno.o:	$(CORE_DEPS) \
	src/os/unix/ngx_errno.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_errno.o \
		src/os/unix/ngx_errno.c


objs/src/os/unix/ngx_alloc.o:	$(CORE_DEPS) \
	src/os/unix/ngx_alloc.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_alloc.o \
		src/os/unix/ngx_alloc.c


objs/src/os/unix/ngx_files.o:	$(CORE_DEPS) \
	src/os/unix/ngx_files.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_files.o \
		src/os/unix/ngx_files.c


objs/src/os/unix/ngx_socket.o:	$(CORE_DEPS) \
	src/os/unix/ngx_socket.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_socket.o \
		src/os/unix/ngx_socket.c


objs/src/os/unix/ngx_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_recv.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_recv.o \
		src/os/unix/ngx_recv.c


objs/src/os/unix/ngx_readv_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_readv_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_readv_chain.o \
		src/os/unix/ngx_readv_chain.c


objs/src/os/unix/ngx_udp_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_recv.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_recv.o \
		src/os/unix/ngx_udp_recv.c


objs/src/os/unix/ngx_send.o:	$(CORE_DEPS) \
	src/os/unix/ngx_send.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_send.o \
		src/os/unix/ngx_send.c


objs/src/os/unix/ngx_writev_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_writev_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_writev_chain.o \
		src/os/unix/ngx_writev_chain.c


objs/src/os/unix/ngx_udp_send.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_send.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_send.o \
		src/os/unix/ngx_udp_send.c


objs/src/os/unix/ngx_udp_sendmsg_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_sendmsg_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_sendmsg_chain.o \
		src/os/unix/ngx_udp_sendmsg_chain.c


objs/src/os/unix/ngx_channel.o:	$(CORE_DEPS) \
	src/os/unix/ngx_channel.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_channel.o \
		src/os/unix/ngx_channel.c


objs/src/os/unix/ngx_shmem.o:	$(CORE_DEPS) \
	src/os/unix/ngx_shmem.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_shmem.o \
		src/os/unix/ngx_shmem.c


objs/src/os/unix/ngx_process.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process.o \
		src/os/unix/ngx_process.c


objs/src/os/unix/ngx_daemon.o:	$(CORE_DEPS) \
	src/os/unix/ngx_daemon.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_daemon.o \
		src/os/unix/ngx_daemon.c


objs/src/os/unix/ngx_setaffinity.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setaffinity.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setaffinity.o \
		src/os/unix/ngx_setaffinity.c


objs/src/os/unix/ngx_setproctitle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setproctitle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setproctitle.o \
		src/os/unix/ngx_setproctitle.c


objs/src/os/unix/ngx_posix_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_posix_init.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_posix_init.o \
		src/os/unix/ngx_posix_init.c


objs/src/os/unix/ngx_user.o:	$(CORE_DEPS) \
	src/os/unix/ngx_user.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_user.o \
		src/os/unix/ngx_user.c


objs/src/os/unix/ngx_dlopen.o:	$(CORE_DEPS) \
	src/os/unix/ngx_dlopen.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_dlopen.o \
		src/os/unix/ngx_dlopen.c


objs/src/os/unix/ngx_process_cycle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process_cycle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process_cycle.o \
		src/os/unix/ngx_process_cycle.c


objs/src/os/unix/ngx_linux_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_init.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_init.o \
		src/os/unix/ngx_linux_init.c


objs/src/event/modules/ngx_epoll_module.o:	$(CORE_DEPS) \
	src/event/modules/ngx_epoll_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/modules/ngx_epoll_module.o \
		src/event/modules/ngx_epoll_module.c


objs/src/os/unix/ngx_linux_sendfile_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_sendfile_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_sendfile_chain.o \
		src/os/unix/ngx_linux_sendfile_chain.c


objs/src/event/ngx_event_openssl.o:	$(CORE_DEPS) \
	src/event/ngx_event_openssl.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_openssl.o \
		src/event/ngx_event_openssl.c


objs/src/event/ngx_event_openssl_stapling.o:	$(CORE_DEPS) \
	src/event/ngx_event_openssl_stapling.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_openssl_stapling.o \
		src/event/ngx_event_openssl_stapling.c


objs/src/core/ngx_regex.o:	$(CORE_DEPS) \
	src/core/ngx_regex.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_regex.o \
		src/core/ngx_regex.c


objs/src/http/ngx_http.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http.o \
		src/http/ngx_http.c


objs/src/http/ngx_http_core_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_core_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_core_module.o \
		src/http/ngx_http_core_module.c


objs/src/http/ngx_http_special_response.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_special_response.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_special_response.o \
		src/http/ngx_http_special_response.c


objs/src/http/ngx_http_request.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request.o \
		src/http/ngx_http_request.c


objs/src/http/ngx_http_parse.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_parse.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_parse.o \
		src/http/ngx_http_parse.c


objs/src/http/modules/ngx_http_log_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_log_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_log_module.o \
		src/http/modules/ngx_http_log_module.c


objs/src/http/ngx_http_request_body.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request_body.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request_body.o \
		src/http/ngx_http_request_body.c


objs/src/http/ngx_http_variables.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_variables.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_variables.o \
		src/http/ngx_http_variables.c


objs/src/http/ngx_http_script.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_script.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_script.o \
		src/http/ngx_http_script.c


objs/src/http/ngx_http_upstream.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream.o \
		src/http/ngx_http_upstream.c


objs/src/http/ngx_http_upstream_round_robin.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream_round_robin.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream_round_robin.o \
		src/http/ngx_http_upstream_round_robin.c


objs/src/http/ngx_http_file_cache.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_file_cache.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_file_cache.o \
		src/http/ngx_http_file_cache.c


objs/src/http/ngx_http_write_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_write_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_write_filter_module.o \
		src/http/ngx_http_write_filter_module.c


objs/src/http/ngx_http_header_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_header_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_header_filter_module.o \
		src/http/ngx_http_header_filter_module.c


objs/src/http/modules/ngx_http_chunked_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_chunked_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_chunked_filter_module.o \
		src/http/modules/ngx_http_chunked_filter_module.c


objs/src/http/v2/ngx_http_v2_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_filter_module.o \
		src/http/v2/ngx_http_v2_filter_module.c


objs/src/http/modules/ngx_http_range_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_range_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_range_filter_module.o \
		src/http/modules/ngx_http_range_filter_module.c


objs/src/http/modules/ngx_http_gzip_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gzip_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gzip_filter_module.o \
		src/http/modules/ngx_http_gzip_filter_module.c


objs/src/http/ngx_http_postpone_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_postpone_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_postpone_filter_module.o \
		src/http/ngx_http_postpone_filter_module.c


objs/src/http/modules/ngx_http_ssi_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_ssi_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_ssi_filter_module.o \
		src/http/modules/ngx_http_ssi_filter_module.c


objs/src/http/modules/ngx_http_charset_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_charset_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_charset_filter_module.o \
		src/http/modules/ngx_http_charset_filter_module.c


objs/src/http/modules/ngx_http_headers_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_headers_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_headers_filter_module.o \
		src/http/modules/ngx_http_headers_filter_module.c


objs/src/http/ngx_http_copy_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_copy_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_copy_filter_module.o \
		src/http/ngx_http_copy_filter_module.c


objs/src/http/modules/ngx_http_not_modified_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_not_modified_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_not_modified_filter_module.o \
		src/http/modules/ngx_http_not_modified_filter_module.c


objs/src/http/v2/ngx_http_v2.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2.o \
		src/http/v2/ngx_http_v2.c


objs/src/http/v2/ngx_http_v2_table.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_table.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_table.o \
		src/http/v2/ngx_http_v2_table.c


objs/src/http/v2/ngx_http_v2_encode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_encode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_encode.o \
		src/http/v2/ngx_http_v2_encode.c


objs/src/http/v2/ngx_http_v2_huff_decode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_huff_decode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_huff_decode.o \
		src/http/v2/ngx_http_v2_huff_decode.c


objs/src/http/v2/ngx_http_v2_huff_encode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_huff_encode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_huff_encode.o \
		src/http/v2/ngx_http_v2_huff_encode.c


objs/src/http/v2/ngx_http_v2_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_module.o \
		src/http/v2/ngx_http_v2_module.c


objs/src/http/modules/ngx_http_static_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_static_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_static_module.o \
		src/http/modules/ngx_http_static_module.c


objs/src/http/modules/ngx_http_gzip_static_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gzip_static_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gzip_static_module.o \
		src/http/modules/ngx_http_gzip_static_module.c


objs/src/http/modules/ngx_http_autoindex_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_autoindex_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_autoindex_module.o \
		src/http/modules/ngx_http_autoindex_module.c


objs/src/http/modules/ngx_http_index_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_index_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_index_module.o \
		src/http/modules/ngx_http_index_module.c


objs/src/http/modules/ngx_http_mirror_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_mirror_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_mirror_module.o \
		src/http/modules/ngx_http_mirror_module.c


objs/src/http/modules/ngx_http_try_files_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_try_files_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_try_files_module.o \
		src/http/modules/ngx_http_try_files_module.c


objs/src/http/modules/ngx_http_auth_basic_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_auth_basic_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_auth_basic_module.o \
		src/http/modules/ngx_http_auth_basic_module.c


objs/src/http/modules/ngx_http_access_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_access_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_access_module.o \
		src/http/modules/ngx_http_access_module.c


objs/src/http/modules/ngx_http_limit_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_conn_module.o \
		src/http/modules/ngx_http_limit_conn_module.c


objs/src/http/modules/ngx_http_limit_req_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_req_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_req_module.o \
		src/http/modules/ngx_http_limit_req_module.c


objs/src/http/modules/ngx_http_realip_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_realip_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_realip_module.o \
		src/http/modules/ngx_http_realip_module.c


objs/src/http/modules/ngx_http_geo_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_geo_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_geo_module.o \
		src/http/modules/ngx_http_geo_module.c


objs/src/http/modules/ngx_http_geoip_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_geoip_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_geoip_module.o \
		src/http/modules/ngx_http_geoip_module.c


objs/src/http/modules/ngx_http_map_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_map_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_map_module.o \
		src/http/modules/ngx_http_map_module.c


objs/src/http/modules/ngx_http_referer_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_referer_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_referer_module.o \
		src/http/modules/ngx_http_referer_module.c


objs/src/http/modules/ngx_http_rewrite_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_rewrite_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_rewrite_module.o \
		src/http/modules/ngx_http_rewrite_module.c


objs/src/http/modules/ngx_http_ssl_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_ssl_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_ssl_module.o \
		src/http/modules/ngx_http_ssl_module.c


objs/src/http/modules/ngx_http_proxy_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_proxy_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_proxy_module.o \
		src/http/modules/ngx_http_proxy_module.c


objs/src/http/modules/ngx_http_fastcgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_fastcgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_fastcgi_module.o \
		src/http/modules/ngx_http_fastcgi_module.c


objs/src/http/modules/ngx_http_uwsgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_uwsgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_uwsgi_module.o \
		src/http/modules/ngx_http_uwsgi_module.c


objs/src/http/modules/ngx_http_scgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_scgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_scgi_module.o \
		src/http/modules/ngx_http_scgi_module.c


objs/src/http/modules/ngx_http_grpc_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_grpc_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_grpc_module.o \
		src/http/modules/ngx_http_grpc_module.c


objs/src/http/modules/perl/ngx_http_perl_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/perl/ngx_http_perl_module.c
	$(CC) -c $(NGX_PERL_CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/perl/ngx_http_perl_module.o \
		src/http/modules/perl/ngx_http_perl_module.c


objs/src/http/modules/ngx_http_secure_link_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_secure_link_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_secure_link_module.o \
		src/http/modules/ngx_http_secure_link_module.c


objs/src/http/modules/ngx_http_upstream_hash_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_hash_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_hash_module.o \
		src/http/modules/ngx_http_upstream_hash_module.c


objs/src/http/modules/ngx_http_upstream_ip_hash_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_ip_hash_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
		src/http/modules/ngx_http_upstream_ip_hash_module.c


objs/src/http/modules/ngx_http_upstream_least_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_least_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
		src/http/modules/ngx_http_upstream_least_conn_module.c


objs/src/http/modules/ngx_http_upstream_random_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_random_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_random_module.o \
		src/http/modules/ngx_http_upstream_random_module.c


objs/src/http/modules/ngx_http_upstream_keepalive_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_keepalive_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
		src/http/modules/ngx_http_upstream_keepalive_module.c


objs/src/http/modules/ngx_http_upstream_zone_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_zone_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_zone_module.o \
		src/http/modules/ngx_http_upstream_zone_module.c


objs/src/http/modules/ngx_http_stub_status_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_stub_status_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_stub_status_module.o \
		src/http/modules/ngx_http_stub_status_module.c


objs/addon/src/log_message_handler.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/log_message_handler.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/log_message_handler.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/log_message_handler.cc


objs/addon/src/ngx_base_fetch.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_base_fetch.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_base_fetch.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_base_fetch.cc


objs/addon/src/ngx_caching_headers.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_caching_headers.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_caching_headers.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_caching_headers.cc


objs/addon/src/ngx_event_connection.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_event_connection.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_event_connection.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_event_connection.cc


objs/addon/src/ngx_fetch.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_fetch.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_fetch.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_fetch.cc


objs/addon/src/ngx_gzip_setter.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_gzip_setter.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_gzip_setter.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_gzip_setter.cc


objs/addon/src/ngx_list_iterator.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_list_iterator.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_list_iterator.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_list_iterator.cc


objs/addon/src/ngx_message_handler.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_message_handler.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_message_handler.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_message_handler.cc


objs/addon/src/ngx_pagespeed.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_pagespeed.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_pagespeed.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_pagespeed.cc


objs/addon/src/ngx_rewrite_driver_factory.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_driver_factory.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_rewrite_driver_factory.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_driver_factory.cc


objs/addon/src/ngx_rewrite_options.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_options.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_rewrite_options.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_rewrite_options.cc


objs/addon/src/ngx_server_context.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_server_context.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_server_context.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_server_context.cc


objs/addon/src/ngx_url_async_fetcher.o:	$(ADDON_DEPS) \
	/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_url_async_fetcher.cc
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_url_async_fetcher.o \
		/root/src/incubator-pagespeed-ngx-latest-stable/src/ngx_url_async_fetcher.cc


objs/addon/src/ngx_http_vhost_traffic_status_module.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_module.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_module.c


objs/addon/src/ngx_http_vhost_traffic_status_variables.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_variables.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_variables.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_variables.c


objs/addon/src/ngx_http_vhost_traffic_status_string.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_string.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_string.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_string.c


objs/addon/src/ngx_http_vhost_traffic_status_shm.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_shm.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_shm.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_shm.c


objs/addon/src/ngx_http_vhost_traffic_status_node.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_node.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_node.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_node.c


objs/addon/src/ngx_http_vhost_traffic_status_filter.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_filter.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_filter.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_filter.c


objs/addon/src/ngx_http_vhost_traffic_status_control.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_control.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_control.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_control.c


objs/addon/src/ngx_http_vhost_traffic_status_limit.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_limit.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_limit.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_limit.c


objs/addon/src/ngx_http_vhost_traffic_status_display.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_display.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display.c


objs/addon/src/ngx_http_vhost_traffic_status_display_json.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_json.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_display_json.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_json.c


objs/addon/src/ngx_http_vhost_traffic_status_display_prometheus.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_prometheus.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_display_prometheus.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_display_prometheus.c


objs/addon/src/ngx_http_vhost_traffic_status_set.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_set.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_set.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_set.c


objs/addon/src/ngx_http_vhost_traffic_status_dump.o:	$(ADDON_DEPS) \
	/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_dump.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_vhost_traffic_status_dump.o \
		/root/src/nginx-module-vts/src/ngx_http_vhost_traffic_status_dump.c


objs/addon/ngx_cache_purge/ngx_cache_purge_module.o:	$(ADDON_DEPS) \
	/root/src/ngx_cache_purge/ngx_cache_purge_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/ngx_cache_purge/ngx_cache_purge_module.o \
		/root/src/ngx_cache_purge/ngx_cache_purge_module.c


objs/addon/src/ngx_http_testcookie_access_module.o:	$(ADDON_DEPS) \
	/root/src/testcookie-nginx-module/src/ngx_http_testcookie_access_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_testcookie_access_module.o \
		/root/src/testcookie-nginx-module/src/ngx_http_testcookie_access_module.c


objs/addon/src/ngx_http_headers_more_filter_module.o:	$(ADDON_DEPS) \
	/root/src/headers-more-nginx-module/src/ngx_http_headers_more_filter_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_filter_module.o \
		/root/src/headers-more-nginx-module/src/ngx_http_headers_more_filter_module.c


objs/addon/src/ngx_http_headers_more_headers_out.o:	$(ADDON_DEPS) \
	/root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_out.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_headers_out.o \
		/root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_out.c


objs/addon/src/ngx_http_headers_more_headers_in.o:	$(ADDON_DEPS) \
	/root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_in.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_headers_in.o \
		/root/src/headers-more-nginx-module/src/ngx_http_headers_more_headers_in.c


objs/addon/src/ngx_http_headers_more_util.o:	$(ADDON_DEPS) \
	/root/src/headers-more-nginx-module/src/ngx_http_headers_more_util.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_util.o \
		/root/src/headers-more-nginx-module/src/ngx_http_headers_more_util.c

objs/addon/src/log_message_handler.o : CFLAGS += --std=c++11
objs/addon/src/ngx_base_fetch.o : CFLAGS += --std=c++11
objs/addon/src/ngx_caching_headers.o : CFLAGS += --std=c++11
objs/addon/src/ngx_event_connection.o : CFLAGS += --std=c++11
objs/addon/src/ngx_fetch.o : CFLAGS += --std=c++11
objs/addon/src/ngx_gzip_setter.o : CFLAGS += --std=c++11
objs/addon/src/ngx_list_iterator.o : CFLAGS += --std=c++11
objs/addon/src/ngx_message_handler.o : CFLAGS += --std=c++11
objs/addon/src/ngx_pagespeed.o : CFLAGS += --std=c++11
objs/addon/src/ngx_rewrite_driver_factory.o : CFLAGS += --std=c++11
objs/addon/src/ngx_rewrite_options.o : CFLAGS += --std=c++11
objs/addon/src/ngx_server_context.o : CFLAGS += --std=c++11
objs/addon/src/ngx_url_async_fetcher.o : CFLAGS += --std=c++11

/root/src/openssl-1.0.2k/.openssl/include/openssl/ssl.h:	objs/Makefile
	cd /root/src/openssl-1.0.2k \
	&& if [ -f Makefile ]; then $(MAKE) clean; fi \
	&& ./config --prefix=/root/src/openssl-1.0.2k/.openssl no-shared no-threads  \
	&& $(MAKE) \
	&& $(MAKE) install_sw LIBDIR=lib


/root/src/zlib-1.2.11/libz.a:	objs/Makefile
	cd /root/src/zlib-1.2.11 \
	&& $(MAKE) distclean \
	&& CFLAGS="-O2 -fomit-frame-pointer -pipe " CC="$(CC)" \
		./configure \
	&& $(MAKE) libz.a


objs/src/http/modules/perl/ngx_http_perl_module.o: \
		objs/src/http/modules/perl/blib/arch/auto/nginx/nginx.so

objs/src/http/modules/perl/blib/arch/auto/nginx/nginx.so: \
		$(CORE_DEPS) $(HTTP_DEPS) \
		src/http/modules/perl/ngx_http_perl_module.h \
		objs/src/http/modules/perl/Makefile
	cd objs/src/http/modules/perl && $(MAKE)

	rm -rf objs/install_perl


objs/src/http/modules/perl/Makefile: \
		objs/ngx_auto_config.h \
		src/core/nginx.h \
		src/http/modules/perl/Makefile.PL \
		src/http/modules/perl/nginx.pm \
		src/http/modules/perl/nginx.xs \
		src/http/modules/perl/typemap
	grep 'define NGINX_VERSION' src/core/nginx.h \
		| sed -e 's/^.*"\(.*\)".*/\1/' > \
		objs/src/http/modules/perl/version
	sed "s/%%VERSION%%/`cat objs/src/http/modules/perl/version`/" \
		src/http/modules/perl/nginx.pm > \
		objs/src/http/modules/perl/nginx.pm
	cp -p src/http/modules/perl/nginx.xs objs/src/http/modules/perl/
	cp -p src/http/modules/perl/typemap objs/src/http/modules/perl/
	cp -p src/http/modules/perl/Makefile.PL objs/src/http/modules/perl/

	cd objs/src/http/modules/perl \
		&& NGX_PM_CFLAGS="$(NGX_PM_CFLAGS) -g " \
			NGX_PM_LDFLAGS=" $(NGX_PM_LDFLAGS)" \
			NGX_INCS="src/core src/event src/event/modules src/os/unix  /root/src/openssl-1.0.2k/.openssl/include /root/src/zlib-1.2.11  objs  src/http src/http/modules src/http/v2 src/http/modules/perl /root/src/incubator-pagespeed-ngx-latest-stable/psol/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/chromium/src /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/src/src /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/google-sparsehash/gen/arch/linux/x64/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/grpc/src/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/protobuf/src/src /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/re2/src /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/out/Release/obj/gen/protoc_out/instaweb /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/src/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/src/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/apr/gen/arch/linux/x64/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/third_party/aprutil/gen/arch/linux/x64/include /root/src/incubator-pagespeed-ngx-latest-stable/psol/include/url" \
			NGX_DEPS="$(CORE_DEPS) $(HTTP_DEPS)" \
		perl Makefile.PL \
			LIB= \
			INSTALLSITEMAN3DIR=


install_perl_modules:
	cd objs/src/http/modules/perl && $(MAKE) install

manpage:	objs/nginx.8

objs/nginx.8:	man/nginx.8 objs/ngx_auto_config.h
	sed -e "s|%%PREFIX%%|/etc/nginx|" \
		-e "s|%%PID_PATH%%|/etc/nginx/logs/nginx.pid|" \
		-e "s|%%CONF_PATH%%|/etc/nginx/nginx.conf|" \
		-e "s|%%ERROR_LOG_PATH%%|/etc/nginx/logs/error.log|" \
		< man/nginx.8 > $@

install:	build install_perl_modules
	test -d '$(DESTDIR)/etc/nginx' || mkdir -p '$(DESTDIR)/etc/nginx'

	test -d '$(DESTDIR)/usr/sbin' \
		|| mkdir -p '$(DESTDIR)/usr/sbin'
	test ! -f '$(DESTDIR)/usr/sbin/nginx' \
		|| mv '$(DESTDIR)/usr/sbin/nginx' \
			'$(DESTDIR)/usr/sbin/nginx.old'
	cp objs/nginx '$(DESTDIR)/usr/sbin/nginx'

	test -d '$(DESTDIR)/etc/nginx' \
		|| mkdir -p '$(DESTDIR)/etc/nginx'

	cp conf/koi-win '$(DESTDIR)/etc/nginx'
	cp conf/koi-utf '$(DESTDIR)/etc/nginx'
	cp conf/win-utf '$(DESTDIR)/etc/nginx'

	test -f '$(DESTDIR)/etc/nginx/mime.types' \
		|| cp conf/mime.types '$(DESTDIR)/etc/nginx'
	cp conf/mime.types '$(DESTDIR)/etc/nginx/mime.types.default'

	test -f '$(DESTDIR)/etc/nginx/fastcgi_params' \
		|| cp conf/fastcgi_params '$(DESTDIR)/etc/nginx'
	cp conf/fastcgi_params \
		'$(DESTDIR)/etc/nginx/fastcgi_params.default'

	test -f '$(DESTDIR)/etc/nginx/fastcgi.conf' \
		|| cp conf/fastcgi.conf '$(DESTDIR)/etc/nginx'
	cp conf/fastcgi.conf '$(DESTDIR)/etc/nginx/fastcgi.conf.default'

	test -f '$(DESTDIR)/etc/nginx/uwsgi_params' \
		|| cp conf/uwsgi_params '$(DESTDIR)/etc/nginx'
	cp conf/uwsgi_params \
		'$(DESTDIR)/etc/nginx/uwsgi_params.default'

	test -f '$(DESTDIR)/etc/nginx/scgi_params' \
		|| cp conf/scgi_params '$(DESTDIR)/etc/nginx'
	cp conf/scgi_params \
		'$(DESTDIR)/etc/nginx/scgi_params.default'

	test -f '$(DESTDIR)/etc/nginx/nginx.conf' \
		|| cp conf/nginx.conf '$(DESTDIR)/etc/nginx/nginx.conf'
	cp conf/nginx.conf '$(DESTDIR)/etc/nginx/nginx.conf.default'

	test -d '$(DESTDIR)/etc/nginx/logs' \
		|| mkdir -p '$(DESTDIR)/etc/nginx/logs'

	test -d '$(DESTDIR)/etc/nginx/logs' \
		|| mkdir -p '$(DESTDIR)/etc/nginx/logs'

	test -d '$(DESTDIR)/etc/nginx/html' \
		|| cp -R html '$(DESTDIR)/etc/nginx'

	test -d '$(DESTDIR)/etc/nginx/logs' \
		|| mkdir -p '$(DESTDIR)/etc/nginx/logs'
