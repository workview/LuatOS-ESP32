/*
 * SPDX-FileCopyrightText: 2021-2022 Darren <1912544842@qq.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
@module  socket
@summary socket操作库
@version 1.0
@date    2022.2.15
*/
#include "luat_base.h"
#include "stdio.h"
#include <string.h>
#include <sys/param.h>
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

static const char *TAG = "lsocket";

/*
创建socket
@api socket.creat(sockType)
@int socket.TCP socket.UDP
@return int sock_handle 用于后续操作
@usage
sock = socket.creat(socket.TCP)
*/
static int l_socket_create(lua_State *L)
{
    int sockType = luaL_checkinteger(L, 1);
    int sock = socket(AF_INET, sockType, IPPROTO_IP);
    lua_pushinteger(L, sock);
    return 1;
}

/*
连接socket
@api socket.connect(sock_handle,ip,port)
@int sock_handle
@string ip
@int port
@return int err
@usage
err = socket.connect(sock, "112.125.89.8", 33863)
log.info("socket","connect",err)
*/
static int l_socket_connect(lua_State *L)
{
    struct sockaddr_in dest_addr;
    size_t len = 0;
    int sock = luaL_checkinteger(L, 1);
    const char *host_ip = luaL_checklstring(L, 2, &len);
    int host_port = luaL_checkinteger(L, 3);

    dest_addr.sin_addr.s_addr = inet_addr(host_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(host_port);

    int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in6));
    fcntl(sock, F_SETFL, O_NONBLOCK);
    lua_pushinteger(L, err);
    return 1;
}

/*
发送数据
@api socket.send(sock_handle,data)
@int sock_handle
@string data
@return int err
@usage
socket.send(sock, "hello lua esp32")
*/
static int l_socket_send(lua_State *L)
{
    size_t len = 0;
    int sock = luaL_checkinteger(L, 1);
    const char *payload = luaL_checklstring(L, 2, &len);
    int err = send(sock, payload, len, 0);
    lua_pushinteger(L, err);
    return 1;
}

/*
接收数据
@api socket.recv(sock_handle)
@int sock_handle
@return string data
@return int len
@usage
local data, len = socket.recv(sock)
*/
static int l_socket_recv(lua_State *L)
{
    int sock = luaL_checkinteger(L, 1);
    char rx_buffer[1024];
    int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
    if (len < 0)
    {
        // ESP_LOGE(TAG, "recv failed: errno %d", errno);
        return 0;
    }
    else
    {
        lua_pushlstring(L, (const char *)rx_buffer, len);
        lua_pushinteger(L, len);
        return 2;
    }
}

/*
销毁socket
@api socket.close(sock_handle)
@int sock_handle
@return none
@usage
socket.close(sock)
*/
static int l_socket_close(lua_State *L)
{
    int sock = luaL_checkinteger(L, 1);
    shutdown(sock, 0);
    close(sock);
    return 0;
}

/*
解析域名
@api socket.dns(addr,port,sockType)
@string 域名
@string 端口,默认80
@int socket类型,默认tcp
@return ip
@usage
socket.dns("wiki.luatos.com")
*/
static int l_socket_dns(lua_State *L)
{
    const char *gaddr = luaL_checkstring(L, 1);
    const char *gport = luaL_optstring(L, 2, "80");

    char buf[100];
    struct sockaddr_in *ipv4 = NULL;
    struct addrinfo *result;

    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = luaL_optinteger(L, 3, SOCK_STREAM),
    };

    getaddrinfo(gaddr, gport, &hints, &result);
    ipv4 = (struct sockaddr_in *)result->ai_addr;
    inet_ntop(result->ai_family, &ipv4->sin_addr, buf, sizeof(buf));

    lua_pushlstring(L, buf, strlen(buf));
    return 1;
}

/*
绑定端口
@api socket.bind(sock_handle,port)
@int sock_handle
@string ip=0
@int port
@return int err
@usage
err = socket.bind(sock, 33863)
log.info("socket","bind",err)

*/

static int l_socket_bind(lua_State *L)
{
    struct sockaddr_in local;
    int err=0; 	
    //struct sockaddr_in dest_addr;
    size_t len = 0;
    int sock = luaL_checkinteger(L, 1);
    //const char *host_ip = luaL_checklstring(L, 2, &len);
    int host_port = luaL_checkinteger(L, 2);

    local.sin_addr.s_addr = IPADDR_ANY;
    local.sin_family      = AF_INET;
    local.sin_port        = htons(host_port);

    err = bind(sock, (struct sockaddr *)&local, sizeof(struct sockaddr_in6));
    //fcntl(sock, F_SETFL, O_NONBLOCK);
    ESP_LOGE(TAG, "bind bind bind success need=0 ----------%d", err);	
    lua_pushinteger(L, err);
    return 1;
}

/*
侦听端口
@api socket.listen(sock_handle,backlog)
@int sock_handle
@int backlog 最大连接数
@return int err
@usage
err = socket.listen(sock, 1)
log.info("socket","listen",err)
*/
//#define MAX_SERVER   1
static int l_socket_listen(lua_State *L)
{
   int sock = luaL_checkinteger(L, 1);
   int backlog = luaL_checkinteger(L, 2);  
   int err = listen(sock, backlog);
   lua_pushinteger(L, err);
   return 1;   
}

/*
接收连接
@api socket.accept(sock_handl)
@int sock_handle
@return int err
@return newsocket sock_conn
@return remote_ip
@usage
newsocket,remote_ip = socket.accept()

*/
static int l_socket_accept(lua_State *L)
{
  int sock = luaL_checkinteger(L, 1); /* server socked */
  int sock_conn=0;		      /* request socked */
  struct sockaddr remote_ip;
  char buf[30];	
  //char *p_buf;	
  socklen_t remote_addrlen;
  sock_conn=accept(sock,&remote_ip,&remote_addrlen);
  if(sock_conn!=-1)
   {
     if(sock_conn!=0)
     {
       ESP_LOGE(TAG, "sock_conn success ----------sock_conn=%d", sock_conn);
     
       struct sockaddr_in *remote_ipa;
       remote_ipa=(struct sockaddr_in *)&remote_ip;	     
       //*p_buf=inet_ntoa( remote_ipa->sin_addr);
       memcpy(buf,inet_ntoa( remote_ipa->sin_addr),strlen(inet_ntoa(remote_ipa->sin_addr)));	     
       ESP_LOGE(TAG, "remote_ip ----------%s", buf  );	     
     } 
   }
  lua_pushinteger(L, sock_conn);
  lua_pushlstring(L, buf, strlen(buf));
  //lua_pushlstring(L, (const char *)&remote_ip, sizeof(struct sockaddr));
  return 1; 
}


#include "rotable.h"
static const rotable_Reg reg_socket[] =
    {
        {"create", l_socket_create, 0},
        {"connect", l_socket_connect, 0},
        {"send", l_socket_send, 0},
        {"recv", l_socket_recv, 0},
        {"close", l_socket_close, 0},
        {"dns", l_socket_dns, 0},
    
        /*@xjf 0323*/ 
	{"bind",l_socket_bind,0},
      	{"listen",l_socket_listen,0},
        {"accept",l_socket_accept,0},
        /*@xjf 0323*/    
    

        {"TCP", NULL, SOCK_STREAM},
        {"UDP", NULL, SOCK_DGRAM},
        {"RAW", NULL, SOCK_RAW},
        {NULL, NULL, 0}};

LUAMOD_API int luaopen_socket(lua_State *L)
{
    luat_newlib(L, reg_socket);
    return 1;
}
