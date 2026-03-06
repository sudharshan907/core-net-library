/*
 * Copyright 2020 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/rule.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/link/ip6tnl.h>

#include "safec_lib_common.h"

#include "libnet_util.h"
#include "libnet.h"

struct neighbour_cb_data {
        struct neighbour_info *neigh_info;
        struct nl_sock *sock;
        int af_filter;                     // Address family filter: 0 for no filter, or AF_INET/AF_INET6.
    };

/**
 * file_write
 * @file_name: File name to write
 * @buf: write buffer
 * @count: No of bytes to be written
 *
 * Write buffer to a file
 */
libnet_status file_write(const char *file_name ,const char *buf, size_t count)
{
        FILE *fp = NULL;
        libnet_status err = CNL_STATUS_FAILURE;

        fp = fopen(file_name, "w");
        if(NULL == fp)
                return err;
        if (0 <= fwrite(buf, sizeof(char), count, fp))
                err = CNL_STATUS_SUCCESS;
        fclose(fp);
        return err;
}

/**
 * file_read
 * @file_name: File name to read
 * @buf: read buffer
 * @count: No of bytes to be read
 *
 * Read from file to buffer
 */
libnet_status file_read(const char *file_name, char *buf, size_t count)
{
        FILE *fp;
        libnet_status err = CNL_STATUS_FAILURE;
        errno_t rc;

        rc = memset_s(buf, count, 0, count);
        ERR_CHK(rc);

        fp = fopen(file_name, "r");
        if(NULL == fp)
                return err;
        if(0 <= fread(buf, sizeof(char), count, fp))
                err = CNL_STATUS_SUCCESS;
        fclose(fp);

        return err;
}

/**
 * vlan_create
 * @if_name: Name of the interface
 * @vid: vlan id
 *
 * Add vlan interface
 */
libnet_status vlan_create(const char *if_name, int vid)
{
        struct rtnl_link *link;
        struct nl_cache *link_cache;
        struct nl_sock *sk;
        int master_index;
        int ret;
        libnet_status err = CNL_STATUS_FAILURE;
        char vlan_if_name[32] = {0};
        errno_t rc;

        rc = sprintf_s(vlan_if_name, sizeof(vlan_if_name), "%s.%d", if_name,vid);
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache) < 0) {
                CNL_LOG_ERROR("Unable to allocate cache\n");
                goto FREE_SOCKET;
        }

        master_index = rtnl_link_name2i(link_cache, if_name);
        if (!master_index) {
                CNL_LOG_ERROR("Unable to lookup interface %s (master_index=%d)\n", 
                        if_name, master_index);
                goto FREE_CACHE;
        }

        if ((link = rtnl_link_vlan_alloc()) == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for vlan\n");
                goto FREE_CACHE;
        }
        rtnl_link_set_link(link, master_index);
        rtnl_link_set_name(link, vlan_if_name);

        ret = rtnl_link_vlan_set_id(link, vid);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set vlan id %d for %s: %s (err=%d)\n",
                        vid, vlan_if_name, nl_geterror(ret), ret);
                goto FREE_VLAN;
        }

        ret = rtnl_link_add(sk, link, NLM_F_CREATE | NLM_F_EXCL);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to add vlan link %s: %s (err=%d)\n",
                        vlan_if_name, nl_geterror(ret), ret);
                goto FREE_VLAN;
        }
        err = CNL_STATUS_SUCCESS;
FREE_VLAN:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * vlan_delete
 * @vlan_name: Name of the vlan interface
 *
 * Remove vlan interface
 */
libnet_status vlan_delete(const char *vlan_name)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if ((link = rtnl_link_alloc()) == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for link\n");
                goto FREE_SOCKET;
        }
        rtnl_link_set_name(link, vlan_name);

        int ret = rtnl_link_delete(sk, link);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to delete vlan %s: %s (err=%d)\n",
                        vlan_name, nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;
FREE_LINK:
        rtnl_link_put(link);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * bridge_create
 * @bridge_name: Name of the bridge interface
 *
 * Add bridge interface
 */
libnet_status bridge_create(const char* bridge_name)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if ((link = rtnl_link_alloc()) == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for link\n");
                goto FREE_SOCKET;
        }
        int ret = rtnl_link_set_type(link, "bridge");
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set link type to bridge for %s: %s (err=%d)\n",
                        bridge_name, nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        rtnl_link_set_name(link, bridge_name);

        ret = rtnl_link_add(sk, link, NLM_F_CREATE | NLM_F_EXCL);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to create bridge %s: %s (err=%d)\n",
                        bridge_name, nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;
FREE_LINK:
        rtnl_link_put(link);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * bridge_delete
 * @bridge_name: Name of the bridge interface
 *
 * Remove bridge interface
 */
libnet_status bridge_delete(const char* bridge_name)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if ((link = rtnl_link_alloc()) == NULL ) {
                CNL_LOG_ERROR("Unable to allocate memory for link\n");
                goto FREE_SOCKET;
        }
        rtnl_link_set_name(link, bridge_name);

        int ret = rtnl_link_delete(sk, link);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to delete bridge %s: %s (err=%d)\n",
                        bridge_name, nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;
FREE_LINK:
        rtnl_link_put(link);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * interface_add_to_bridge
 * @bridge_name: Name of the bridge
 * @if_name: slave interface name
 *
 * Add interface to bridge
 */
libnet_status interface_add_to_bridge(const char* bridge_name, const char* if_name)
{
        struct nl_sock *sk;
        struct nl_cache *link_cache;
        struct rtnl_link *link;
        struct rtnl_link *ltap;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache for bridge operation (bridge=%s, interface=%s): %s (err=%d)\n",
                        bridge_name, if_name, nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        link = rtnl_link_get_by_name(link_cache, bridge_name);
        if (!link) {
                CNL_LOG_ERROR("Unable to find the bridge '%s'\n", bridge_name);
                goto FREE_CACHE;
        }

        ltap = rtnl_link_get_by_name(link_cache, if_name);
        if (!ltap) {
                CNL_LOG_ERROR("Unable to find the interface '%s'\n", if_name);
                goto FREE_LINK;
        }

        ret = rtnl_link_enslave(sk, link, ltap);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to enslave %s to bridge %s: %s (err=%d)\n",
                        if_name, bridge_name, nl_geterror(ret), ret);
                goto FREE_LINK2;
        }
        err = CNL_STATUS_SUCCESS;
FREE_LINK2:
        rtnl_link_put(ltap);
FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * interface_remove_from_bridge
 * @if_name: slave interface name
 *
 * Remove interface from bridge
 */
libnet_status interface_remove_from_bridge (const char *if_name)
{
        struct nl_sock *sk;
        struct nl_cache *link_cache;
        struct rtnl_link *ltap;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache for interface '%s': %s (err=%d)\n",
                        if_name, nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        ltap = rtnl_link_get_by_name(link_cache, if_name);
        if (!ltap) {
                CNL_LOG_ERROR("Unable to find the interface '%s'\n", if_name);
                goto FREE_CACHE;
        }

        ret = rtnl_link_release(sk, ltap);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to release %s from bridge: %s (err=%d)\n",
                        if_name, nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;
FREE_LINK:
        rtnl_link_put(ltap);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * bridge_set_stp
 * @bridge_name: Name of the bridge
 * @val: To enable STP or not ("off" if disabled, "on" if enabled)
 *
 * Enable/Disable spanning tree protocol for bridge interface
 */
libnet_status bridge_set_stp(const char *bridge_name, char *val)
{
        char file_name[64] = {0};
        char buf[2] = {0};
        int len = (val != NULL ? strlen(val) : 0);
        int off = 0, on = 0;
        int stp_state;
        errno_t rc;

        if (len == 3)
        {
                off = (strncmp(val, "off", 3) == 0 ? 1 : 0);
        }
        else if (len == 2)
        {
                on = (strncmp(val, "on", 2) == 0 ? 1 : 0);
        }

        if ((off == 0 && on == 0) ||
            (off == 1 && on == 1))
        {
                CNL_LOG_ERROR("val must be on or off\n");
                return CNL_STATUS_FAILURE;
        }

        stp_state = CNL_STATUS_FAILURE;

        if (off == 1)
        {
                // Off
                stp_state = (int) STP_DISABLED;
        }
        else
        {
                // On
                stp_state = (int) STP_LISTENING;
        }

        rc = sprintf_s(file_name, sizeof(file_name), "/sys/class/net/%s/bridge/stp_state",
                       bridge_name);
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        if (-1 == access(file_name, F_OK | W_OK))
        {
                CNL_LOG_ERROR("file_name %s does not exist or is not writeable\n",
                              file_name);
                return CNL_STATUS_FAILURE;
        }

        buf[0] = (char) stp_state + '0';
        return file_write(file_name, buf, strlen(buf) + 1);
}

/**
 * interface_up
 * @if_name: interface name
 *
 * Set interface state as UP
 */
libnet_status interface_up(char *if_name)
{
        struct nl_sock *sk;
        struct rtnl_link *link;
        struct rtnl_link *change;
        struct nl_cache *cache;
        libnet_status err = CNL_STATUS_FAILURE;
        CNL_LOG_ERROR(" %s:sudh 1 interface_up called for ifname\n",
                        if_name);
FILE *fp = fopen("/tmp/sudh.txt", "a");
        
if (fp) {
                fprintf(fp, "[interface_up] 1: if_name=%s\n", if_name ? if_name : "(null)");
       }

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                if (fp) {
                fprintf(fp, "[interface_up] 2: if_name=%s\n", if_name ? if_name : "(null)");
       }
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                if (fp) {
                fprintf(fp, "[interface_up] 3: if_name=%s\n", if_name ? if_name : "(null)");
       }
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                if (fp) {
                fprintf(fp, "[interface_up] 4: if_name=%s\n", if_name ? if_name : "(null)");
       }
                goto FREE_SOCKET;
        }

        if (!(link = rtnl_link_get_by_name(cache, if_name))) {
                CNL_LOG_ERROR("Interface '%s' not found\n", if_name);
                if (fp) {
                fprintf(fp, "[interface_up] 5: if_name=%s\n", if_name ? if_name : "(null)");
       }
                goto FREE_CACHE;
        }

        unsigned int flags = rtnl_link_get_flags(link);
        if (flags & IFF_UP) {
                if (fp) {
                fprintf(fp, "[interface_up] 6: if_name=%s\n", if_name ? if_name : "(null)");
       }
                err = CNL_STATUS_SUCCESS;
                goto FREE_LINK;
        }

        change = rtnl_link_alloc();
        if (fp) {
                fprintf(fp, "[interface_up] 7: if_name=%s\n", if_name ? if_name : "(null)");
       }

        flags |= IFF_UP;
 if (fp) {
                fprintf(fp, "[interface_up] 8: if_name=%s\n", if_name ? if_name : "(null)");
       }
        rtnl_link_set_flags(change, flags);
        if (fp) {
                fprintf(fp, "[interface_up] 9: if_name=%s\n", if_name ? if_name : "(null)");
       }
        ret = rtnl_link_change(sk, link, change, 0);
        if (fp) {
                fprintf(fp, "[interface_up] 11: if_name=%s\n", if_name ? if_name : "(null)");
       }
        if (ret < 0) {
                CNL_LOG_ERROR("sudh Unable to bring up interface %s: %s (err=%d)\n",
                        if_name, nl_geterror(ret), ret);
                CNL_LOG_ERROR(" %s:sudh 2 interface_up called for ifname\n",
                        if_name);
                
                if (fp) {
                fprintf(fp, "[interface_up] 12: if_name=%s\n", if_name ? if_name : "(null)");
       }
                goto FREE_LINK2;
        }

        err = CNL_STATUS_SUCCESS;
        if (fp) {
                fprintf(fp, "[interface_up] 13: if_name=%s\n", if_name ? if_name : "(null)");
       }
FREE_LINK2:
        rtnl_link_put(change);
FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(cache);
FREE_SOCKET:
        nl_socket_free(sk);
        CNL_LOG_ERROR(" %s:sudh 3 interface_up called for ifname error returning %d\n",
                        if_name,err);
if (fp) {
                fprintf(fp, "[interface_up] 14: if_name=%s\n", if_name ? if_name : "(null)");
       }
        return err;
}
/**
 * interface_down
 * @if_name: interface name
 *
 * Set interface state as DOWN
 */
libnet_status interface_down(char *if_name)
{
        struct nl_sock *sk;
        struct rtnl_link *link;
        struct rtnl_link *change;
        struct nl_cache *cache;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache for interface '%s': %s (err=%d)\n",
                        if_name, nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        if (!(link = rtnl_link_get_by_name(cache, if_name))) {
                CNL_LOG_ERROR("Interface '%s' not found\n", if_name);
                goto FREE_CACHE;
        }

        unsigned int flags = rtnl_link_get_flags(link);
        if (!(flags & IFF_UP)) {
                err = CNL_STATUS_SUCCESS;
                goto FREE_LINK;
        }

        change = rtnl_link_alloc();
        rtnl_link_unset_flags(change, IFF_UP);

        ret = rtnl_link_change(sk, link, change, 0);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to bring down interface %s: %s (err=%d)\n",
                        if_name, nl_geterror(ret), ret);
                goto FREE_LINK2;
        }

        err = CNL_STATUS_SUCCESS;
FREE_LINK2:
        rtnl_link_put(change);
FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(cache);
FREE_SOCKET:
        nl_socket_free(sk);
        return err;
}

/**
 * interface_exist
 * @if_name: interface name
 *
 * Check the interface existence
 */
int interface_exist(const char *if_name)
{
        char file_name[64] = {0};
        errno_t rc;

        rc = sprintf_s(file_name, sizeof(file_name), "/sys/class/net/%s", if_name);
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        if (0 == access(file_name, F_OK))
                return CNL_STATUS_SUCCESS;
        return CNL_STATUS_FAILURE;
}

/**
 * interface_set_mtu
 * @if_name: interface name
 * @val: new mtu value
 *
 * Set mtu fo an interface
 */
libnet_status interface_set_mtu(const char *if_name, char *val)
{
        char file_name[64] = {0};
        errno_t rc;

        rc = sprintf_s(file_name, sizeof(file_name), "/sys/class/net/%s/mtu", if_name);
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        return file_write(file_name, val, strlen(val) + 1);
}

/**
 * interface_get_mac
 * @if_name: interface name
 * @mac: read buffer for mac
 * @size: mac buffer size
 *
 * Get mac address of an interface
 */
libnet_status interface_get_mac(const char *if_name, char *mac, size_t size)
{
        char file_name[64] = {0};
        libnet_status err = CNL_STATUS_FAILURE;
        errno_t rc;

        rc = sprintf_s(file_name, sizeof(file_name), "/sys/class/net/%s/address", if_name);
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        err = file_read(file_name, mac, size);
        if (err != CNL_STATUS_FAILURE) {
                while (*mac != '\0')
                        mac++;
                if (*(--mac) == '\n')
                        *mac = '\0';
        }
        return err;
}

/**
 * interface_set_mac
 * @if_name: interface name
 * @mac: write buffer for mac
 *
 * Set mac address of an interface
 */
libnet_status interface_set_mac(const char *if_name, char *mac)
{
        struct ifreq if_req = {0};
        int sock;

        int ret = sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                         &if_req.ifr_hwaddr.sa_data[0],
                         &if_req.ifr_hwaddr.sa_data[1],
                         &if_req.ifr_hwaddr.sa_data[2],
                         &if_req.ifr_hwaddr.sa_data[3],
                         &if_req.ifr_hwaddr.sa_data[4],
                         &if_req.ifr_hwaddr.sa_data[5]
                );

        if (ret != 6 || strlen(mac) != 17)
        {
                CNL_LOG_ERROR("Input MAC Address must be of format: ab:cd:ef:gh:ij:kl\n");
                return CNL_STATUS_FAILURE;
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);

        if (sock < 0)
        {
                CNL_LOG_ERROR("Error creating socket\n");
                return CNL_STATUS_FAILURE;
        }

        snprintf(if_req.ifr_name, sizeof(if_req.ifr_name), "%s", if_name);
        if_req.ifr_hwaddr.sa_family = ARPHRD_ETHER;

        if(ioctl(sock, SIOCSIFHWADDR, &if_req) < 0)
        {
                CNL_LOG_ERROR("Failed to set MAC Address\n");
                close(sock);
                return CNL_STATUS_FAILURE;
        }

        close(sock);
        return CNL_STATUS_SUCCESS;
}

/**
 * interface_get_ip
 * @if_name: interface name
 *
 * Get the ip address of an interface
 */
char* interface_get_ip(const char* if_name)
{
        struct ifreq if_req = {0};
        int sock;

        if ((sock = socket(AF_INET, SOCK_DGRAM, 0) ) < 0) {
                CNL_LOG_ERROR("Socket error: %s\n", strerror(errno));
                return NULL;
        }
        if_req.ifr_addr.sa_family = AF_INET;
        strncpy(if_req.ifr_name, if_name, IFNAMSIZ-1);
        if ( ioctl(sock, SIOCGIFADDR, &if_req)  < 0 )
        {
                CNL_LOG_ERROR("Failed to get %s IP Address\n", if_name);
                close(sock);
                return NULL;
        }
        close(sock);
        return (inet_ntoa(((struct sockaddr_in *)&if_req.ifr_addr)->sin_addr));
}

/**
 * interface_set_netmask
 * @if_name: interface name
 * @netmask: netmask
 * Set the netmask address of an interface
 */
libnet_status interface_set_netmask(const char* if_name, const char *netmask)
{
        struct ifreq if_req = {0};
        struct sockaddr_in sin;
        int sock;

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        sin.sin_family = AF_INET;

        if (inet_aton(netmask,&sin.sin_addr) != 1)
        {
                CNL_LOG_ERROR("Failed to parse %s netmask address\n", if_name);
                close(sock);
                return CNL_STATUS_FAILURE;
        }

        strncpy(if_req.ifr_name, if_name, IFNAMSIZ-1);
        memcpy(&if_req.ifr_netmask, &sin, sizeof(struct sockaddr));

        if (ioctl(sock, SIOCSIFNETMASK, &if_req) < 0) {
                CNL_LOG_ERROR("Failed to set %s netmask address\n", if_name);
                close(sock);
                return CNL_STATUS_FAILURE;
        }
        close(sock);
        return CNL_STATUS_SUCCESS;
}

/**
 * addr_derive_broadcast
 * @ip: IP address of the interface
 * @prefix_len: address bits (excluding broadcast bits)
 * @bcast: broadcast address
 * @size: broadcast buffer size
 *
 * Derive broadcast address using ip & prefix values
 */
libnet_status addr_derive_broadcast(char *ip, unsigned int prefix_len, char *bcast, int size)
{
        struct in_addr inaddr;

        if (inet_pton(AF_INET, ip, &inaddr) < 1)
                return CNL_STATUS_FAILURE;
        inaddr.s_addr |= htonl(~(~0U << (32U - prefix_len)));
        inet_ntop(AF_INET, &inaddr, bcast, size);
        return CNL_STATUS_SUCCESS;
}

/**
 * addr_add
 * @args: ip address, [netmask, broadcast & family]
 *
 * Configure interface ip configurations
 */
libnet_status addr_add(char *args)
{
        struct nl_sock *sock;
        struct rtnl_addr *addr;
        struct nl_cache *link_cache;
        libnet_status err = CNL_STATUS_FAILURE;

        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        char *str = strdup(args);
        char *token;
        char *saveptr;

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link_cache = libnet_link_alloc_cache(sock);
        if (link_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate link cache\n");
                goto FREE_SOCKET;
        }

        addr = libnet_addr_alloc();
        if (addr == NULL) {
                CNL_LOG_ERROR("Unable to allocate addr\n");
                goto FREE_CACHE;
        }

        token = strtok_r(str, " ", &saveptr);
        while( token != NULL) {
                if(0 == strcmp(token, "dev")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_dev(addr, link_cache, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse dev field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "valid_lft")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_valid(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse valid_lft field \n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "preferred_lft")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_preferred(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse preferred_lft field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "broadcast")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_broadcast(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse broadcast field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        rtnl_addr_set_family(addr, AF_INET);
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        rtnl_addr_set_family(addr, AF_INET6);
                } else {
                        if (libnet_addr_parse_local(addr, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse local field\n",
                                              args);
                                goto FREE_ADDR;
                        }
                }
                token = strtok_r(NULL, " ", &saveptr);
        }

        int ret = rtnl_addr_add(sock, addr, NLM_F_EXCL);
        if (ret < 0) {
                CNL_LOG_ERROR("%s: Unable to add addr: %s (err=%d)\n",
                        args, nl_geterror(ret), ret);
                goto FREE_ADDR;
        }
        err = CNL_STATUS_SUCCESS;

FREE_ADDR:
        rtnl_addr_put(addr);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sock);

        free(str);
        return err;
}

static void addr_delete_cb(struct nl_object *obj, void *arg)
{
        struct rtnl_addr *addr = (struct rtnl_addr *) obj;
        struct nl_sock *sock = (struct nl_sock *) arg;
        libnet_status err = CNL_STATUS_SUCCESS;

        if ((err = rtnl_addr_delete(sock, addr, 0)) < 0)
                CNL_LOG_ERROR("Unable to delete addr: %s (err=%d)\n",
                        nl_geterror(err), err);
}

/**
 * addr_delete
 * @args: ip address, [netmask, broadcast & family]
 *
 * Delete ip address of an interface
 */
libnet_status addr_delete(char *args)
{
        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        char *str = strdup(args);
        char *token;
        char *saveptr;
        int family = AF_UNSPEC;

        struct nl_sock *sock;
        struct nl_cache *link_cache;
        struct nl_cache *addr_cache;
        struct rtnl_addr *addr;
        libnet_status err = CNL_STATUS_FAILURE;

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                free(str);
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE)< 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link_cache = libnet_link_alloc_cache(sock);
        if (link_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate link cache\n");
                goto FREE_SOCKET;
        }

        addr_cache = libnet_addr_alloc_cache(sock);
        if (addr_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate addr cache\n");
                goto FREE_LINK_CACHE;
        }

        addr = libnet_addr_alloc();
        if (addr == NULL) {
                CNL_LOG_ERROR("Unable to allocate addr\n");
                goto FREE_ADDR_CACHE;
        }

        token = strtok_r(str, " ", &saveptr);
        while( token != NULL) {
                if(0 == strcmp(token, "dev")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_dev(addr, link_cache, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse dev field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "valid_lft")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_valid(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse valid_lft field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "preferred_lft")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_preferred(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse preferred_lft field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "broadcast")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse_broadcast(addr, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse broadcast field\n", args);
                                        goto FREE_ADDR;
                                }
                        }
                } else if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        rtnl_addr_set_family(addr, AF_INET);
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        rtnl_addr_set_family(addr, AF_INET6);
                } else {
                        if (libnet_addr_parse_local(addr, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse local field\n", args);
                                goto FREE_ADDR;
                        }
                }
                token = strtok_r(NULL, " ", &saveptr);
        }

        int ret = rtnl_addr_delete(sock, addr, 0);
        if (ret < 0) {
                CNL_LOG_ERROR("%s: Unable to del addr: %s (err=%d)\n",
                        args, nl_geterror(ret), ret);
                goto FREE_ADDR;
        }
        err = CNL_STATUS_SUCCESS;

FREE_ADDR:
        rtnl_addr_put(addr);
FREE_ADDR_CACHE:
        nl_cache_free(addr_cache);
FREE_LINK_CACHE:
        nl_cache_free(link_cache);

FREE_SOCKET:
        nl_socket_free(sock);

        free(str);
        return err;
}

/**
 * @brief Add routing table entry.
 *
 * @param args Routing configuration [default, device, table, via].
 * @return libnet_status Status of the operation.
 */
libnet_status route_add(char *args)
{
        struct nl_sock *sock;
        struct rtnl_route *route;
        struct nl_cache *link_cache;
        libnet_status err = CNL_STATUS_FAILURE;

        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        char *str = strdup(args);
        char *token;
        char *saveptr;
        char nexthop[64]={0};
        char metric[64]={0};

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                free(str);
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link_cache = libnet_link_alloc_cache(sock);
        if (link_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate link cache\n");
                goto FREE_SOCKET;
        }

        route = libnet_route_alloc();
        if (route == NULL) {
                CNL_LOG_ERROR("Unable to allocate route\n");
                goto FREE_LINK_CACHE;
        }

        int ret;
        token = strtok_r(str, " ", &saveptr);
        while( token != NULL) {
                if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        ret = rtnl_route_set_family(route, AF_INET);
                        if (ret < 0) {
                                CNL_LOG_ERROR("%s: Unable to set V4 addr: %s (err=%d)\n",
                                        args, nl_geterror(ret), ret);
                                goto FREE_ROUTE;
                        }
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        ret = rtnl_route_set_family(route, AF_INET6);
                        if (ret < 0) {
                                CNL_LOG_ERROR("%s: Unable to set V6 addr: %s (err=%d)\n",
                                        args, nl_geterror(ret), ret);
                                goto FREE_ROUTE;
                        }
                } else if (0 == strcmp(token, "default")) {
                        if (libnet_route_parse_dst(route, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse dst field\n", args);
                                goto FREE_ROUTE;
                        }
                } else if(0 == strcmp(token, "dev")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(nexthop,"dev=");
                                strcat(nexthop,token);
                                strcat(nexthop,",");
                        }
                } else if(0 == strcmp(token, "via")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(nexthop,"via=");
                                strcat(nexthop,token);
                                strcat(nexthop,",");
                        }
                } else if(0 == strcmp(token, "src")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_pref_src(route, token) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse src field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "metric")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_prio(route, token) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse metric field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "mtu")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(metric,"mtu=");
                                strcat(metric,token);
                                strcat(metric,",");
                                if (libnet_route_parse_metric(route, metric) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse mtu field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "table")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_table(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse table field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "proto") || 0 == strcmp(token, "protocol")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_protocol(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse proto field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "scope")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_scope(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse scope field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "type")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_type(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse type field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else {
                        if (libnet_route_parse_dst(route, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse dst field\n", args);
                                goto FREE_ROUTE;
                        }
                }
                token = strtok_r(NULL, " ", &saveptr);
        }

        if (libnet_route_parse_nexthop(route, nexthop, link_cache) != 0) {
                CNL_LOG_ERROR("%s: Unable to parse nexthop field\n", args);
                goto FREE_ROUTE;
        }

        ret = rtnl_route_add(sock, route, NLM_F_CREATE | NLM_F_REPLACE);
        if (ret < 0) {
                CNL_LOG_ERROR("%s: Unable to add route: %s (err=%d)\n",
                        args, nl_geterror(ret), ret);
                goto FREE_ROUTE;
        }
        err = CNL_STATUS_SUCCESS;

FREE_ROUTE:
        rtnl_route_put(route);
FREE_LINK_CACHE:
        nl_cache_free(link_cache);

FREE_SOCKET:
        nl_socket_free(sock);

        free(str);
        return err;
}

static void route_delete_cb(struct nl_object *obj, void *arg)
{
        struct rtnl_route *route = (struct rtnl_route *) obj;
        struct nl_sock *sock = (struct nl_sock *) arg;
        libnet_status err = CNL_STATUS_SUCCESS;

        if ((err = rtnl_route_delete(sock, route, 0)) < 0)
                CNL_LOG_ERROR("Unable to delete route - Returned err = %d\n", err);
}

/**
 * @brief Delete routing table entry.
 *
 * @param args Routing configuration [default, device, table, via].
 * @return libnet_status Status of the operation.
 */
libnet_status route_delete(char *args)
{
        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        struct nl_sock *sock;
        struct nl_cache *link_cache;
        struct nl_cache *route_cache;
        struct rtnl_route *route;
        libnet_status err = CNL_STATUS_FAILURE;
        char *str = strdup(args);
        char *token;
        char *saveptr;
        char nexthop[64]={0};
        char metric[64]={0};

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                free(str);
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link_cache = libnet_link_alloc_cache(sock);
        if (link_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate link cache\n");
                goto FREE_SOCKET;
        }

        route_cache = libnet_route_alloc_cache(sock, 0);
        if (route_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate route cache\n");
                goto FREE_LINK_CACHE;
        }

        route = libnet_route_alloc();
        if (route == NULL) {
                CNL_LOG_ERROR("Unable to allocate route\n");
                goto FREE_ROUTE_CACHE;
        }

        int ret;
        token = strtok_r(str, " ", &saveptr);
        while (token != NULL) {
                if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        ret = rtnl_route_set_family(route, AF_INET);
                        if (ret < 0) {
                                CNL_LOG_ERROR("%s: Unable to set V4 addr: %s (err=%d)\n",
                                        args, nl_geterror(ret), ret);
                                goto FREE_ROUTE;
                        }
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        ret = rtnl_route_set_family(route, AF_INET6);
                        if (ret < 0) {
                                CNL_LOG_ERROR("%s: Unable to set V6 addr: %s (err=%d)\n",
                                        args, nl_geterror(ret), ret);
                                goto FREE_ROUTE;
                        }
                } else if (0 == strcmp(token, "default")) {
                        if (libnet_route_parse_dst(route, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse dst field\n", args);
                                goto FREE_ROUTE;
                        }
                } else if(0 == strcmp(token, "dev")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(nexthop,"dev=");
                                strcat(nexthop,token);
                                strcat(nexthop,",");
                        }
                } else if(0 == strcmp(token, "via")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(nexthop,"via=");
                                strcat(nexthop,token);
                                strcat(nexthop,",");
                        }
                } else if(0 == strcmp(token, "src")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_pref_src(route, token) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse src field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "metric")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_prio(route, token) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse metric field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "mtu")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                strcat(metric,"mtu=");
                                strcat(metric,token);
                                strcat(metric,",");
                                if (libnet_route_parse_metric(route, metric) < 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse mtu field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "table")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_table(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse table field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "proto") || 0 == strcmp(token, "protocol")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_protocol(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse proto field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "scope")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_scope(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse scope field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
                } else if(0 == strcmp(token, "type")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_route_parse_type(route, token) != 0) {
                                        CNL_LOG_ERROR("%s: Unable to parse type field\n", args);
                                        goto FREE_ROUTE;
                                }
                        }
               } else  {
                        if (libnet_route_parse_dst(route, token) != 0) {
                                CNL_LOG_ERROR("%s: Unable to parse dst field\n", args);
                                goto FREE_ROUTE;
                        }
                }
                token = strtok_r(NULL, " ", &saveptr);
        }

        if (strlen(nexthop) > 0) {
                if (libnet_route_parse_nexthop(route, nexthop, link_cache) != 0) {
                        CNL_LOG_ERROR("%s: Unable to parse nexthop field\n", args);
                        goto FREE_ROUTE;
                }
        }

        nl_cache_foreach_filter(route_cache, OBJ_CAST(route), route_delete_cb, (void *)sock);
        err = CNL_STATUS_SUCCESS;
FREE_ROUTE:
        rtnl_route_put(route);
FREE_ROUTE_CACHE:
        nl_cache_free(route_cache);
FREE_LINK_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sock);
        free(str);

        return err;
}

/**
 * rule_add
 * @args: policy routing configuration [input interface, output interface, table]
 *
 * Add policy routing table entry
 */
libnet_status rule_add(char *args)
{
        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        char *str = strdup(args);
        char *token;
        char *saveptr;

        struct nl_sock *sock;
        struct rtnl_rule *rule;
        libnet_status err = CNL_STATUS_FAILURE;
        int family = AF_UNSPEC;
        struct nl_addr *src = NULL;
        struct nl_addr *dst = NULL;

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                free(str);
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        rule = libnet_rule_alloc();

        if (rule == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for rule\n");
                goto FREE_SOCKET;
        }

        if (libnet_addr_parse("all", family, &src) != 0) {
                goto FREE_RULE;
        }

        int ret = rtnl_rule_set_src(rule, src);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set rule src (family=%d): %s (err=%d)\n",
                        family, nl_geterror(ret), ret);
                goto FREE_RULE;
        }

        rtnl_rule_set_action(rule, RTN_UNICAST);

        token = strtok_r(str, " ", &saveptr);
        while( token != NULL) {
                if(0 == strcmp(token, "from")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse(token, family, &src) != 0) {
                                        CNL_LOG_ERROR("Unable to parse rule src\n");
                                        goto FREE_RULE;
                                }
                                ret = rtnl_rule_set_src(rule, src);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule src: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        } else {
                                CNL_LOG_ERROR("'from' option not provided\n");
                                goto FREE_RULE;
                        }
                } else if (0 == strcmp(token, "to")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse(token, family, &dst) != 0) {
                                        CNL_LOG_ERROR("Unable to parse rule dst\n");
                                        goto FREE_RULE;
                                }
                                ret = rtnl_rule_set_dst(rule, dst);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule dst: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        } else {
                                CNL_LOG_ERROR("'to' option not provided\n");
                                goto FREE_RULE;
                        }
                } else if(0 == strcmp(token, "iif")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                ret = rtnl_rule_set_iif(rule, token);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule iif: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        } else {
                                CNL_LOG_ERROR("'iif' option not provided\n");
                                goto FREE_RULE;
                        }
                } else if(0 == strcmp(token, "oif")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                ret = rtnl_rule_set_oif(rule, token);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule oif: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        } else {
                                CNL_LOG_ERROR("'oif' option not provided\n");
                                goto FREE_RULE;
                        }
                } else if(0 == strcmp(token, "lookup") ||
                          0 == strcmp(token, "table")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (rtnl_route_read_table_names(
                                            "/etc/iproute2/rt_tables") < 0) {
                                        CNL_LOG_ERROR("Failed to read %s\n",
                                                      "/etc/iproute2/rt_tables");
                                        goto FREE_RULE;
                                }
                                int tableId = rtnl_route_str2table(token);
                                if (tableId < 0) {
                                        CNL_LOG_ERROR("No such table %s\n", token);
                                        goto FREE_RULE;
                                }
                                rtnl_rule_set_table(rule, tableId);
                                rtnl_rule_set_action(rule, FR_ACT_TO_TBL);
                        } else {
                                CNL_LOG_ERROR("'table/lookup' option not provided\n");
                                goto FREE_RULE;
                        }
                } else if (0 == strcmp(token, "prio")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                rtnl_rule_set_prio(rule, atoi(token));
                        } else {
                                CNL_LOG_ERROR("'priority' option not provided\n");
                        }
                } else if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        family = AF_INET;
                        rtnl_rule_set_family(rule, family);
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        family = AF_INET6;
                        rtnl_rule_set_family(rule, family);
                }
                token = strtok_r(NULL, " ", &saveptr);
        }

        ret = rtnl_rule_add(sock, rule, NLM_F_EXCL);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to add rule: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_RULE;
        }
        err = CNL_STATUS_SUCCESS;

FREE_RULE:
        rtnl_rule_put(rule);
        nl_addr_put(src);
        nl_addr_put(dst);
FREE_SOCKET:
        nl_socket_free(sock);

        free(str);
        return err;
}

static void rule_delete_cb(struct nl_object *obj, void *arg)
{
        struct rtnl_rule *rule = (struct rtnl_rule *) obj;
        struct nl_sock *sock = (struct nl_sock *) arg;
        libnet_status err = CNL_STATUS_SUCCESS;

        if ((err = rtnl_rule_delete(sock, rule, 0)) < 0)
                CNL_LOG_ERROR("Unable to delete rule: %s (err=%d)\n",
                        nl_geterror(err), err);
}

/**
 * rule_delete
 * @args: policy routing configuration [input interface, output interface, table]
 *
 * Remove policy routing table entry
 */
libnet_status rule_delete(char *args)
{
        CNL_LOG_INFO("Entering with args: '%s'\n", args);

        char *str = strdup(args);
        char *token;
        char *saveptr;
        int family = AF_UNSPEC;
        int ret = 0;

        struct nl_sock *sock;
        struct nl_cache *rule_cache;
        struct rtnl_rule *rule;
        struct nl_addr *src = NULL;
        struct nl_addr *dst = NULL;
        libnet_status err = CNL_STATUS_FAILURE;

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                free(str);
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        rule_cache = libnet_rule_alloc_cache(sock);
        if (rule_cache == NULL) {
                CNL_LOG_ERROR("Unable to allocate rule cache\n");
                goto FREE_SOCKET;
        }

        rule = libnet_rule_alloc();
        if (rule == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for rule\n");
                goto FREE_CACHE;
        }

        token = strtok_r(str, " ", &saveptr);
        while( token != NULL) {
                if(0 == strcmp(token, "from")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse(token, family, &src) != 0) {
                                        CNL_LOG_ERROR("Unable to parse rule src addr\n");
                                        goto FREE_RULE;
                                }
                                ret = rtnl_rule_set_src(rule, src);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule src: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        }
                } else if (0 == strcmp(token, "to")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                if (libnet_addr_parse(token, family, &dst) != 0) {
                                        CNL_LOG_ERROR("Unable to parse rule dst addr\n");
                                        goto FREE_RULE;
                                }
                                if (rtnl_rule_set_dst(rule, dst) < 0) {
                                        CNL_LOG_ERROR("Unable to set rule dst\n");
                                        goto FREE_RULE;
                                }
                        }
                } else if(0 == strcmp(token, "iif")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                ret = rtnl_rule_set_iif(rule, token);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule iif: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        }
                } else if(0 == strcmp(token, "oif")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                ret = rtnl_rule_set_oif(rule, token);
                                if (ret < 0) {
                                        CNL_LOG_ERROR("Unable to set rule oif: %s (err=%d)\n",
                                                nl_geterror(ret), ret);
                                        goto FREE_RULE;
                                }
                        }
                } else if(0 == strcmp(token, "lookup") ||
                          0 == strcmp(token, "table")) {
                        token = strtok_r(NULL, " ", &saveptr);
                        if (token != NULL) {
                                int tableId = rtnl_route_str2table(token);
                                if (tableId < 0) {
                                        CNL_LOG_ERROR("No such table %s\n", token);
                                        goto FREE_RULE;
                                }
                                rtnl_rule_set_table(rule, tableId);
                                rtnl_rule_set_action(rule, FR_ACT_TO_TBL);
                        }
                } else if(0 == strcmp(token, "-4") || 0 == strcmp(token, "4") ||
                          0 == strcmp(token, "inet")) {
                        family = AF_INET;
                        rtnl_rule_set_family(rule, family);
                } else if(0 == strcmp(token, "-6") || 0 == strcmp(token, "6") ||
                          0 == strcmp(token, "inet6")) {
                        family = AF_INET6;
                        rtnl_rule_set_family(rule, family);
                }
                token = strtok_r(NULL, " ", &saveptr);
        }
        nl_cache_foreach_filter(rule_cache, OBJ_CAST(rule), rule_delete_cb, (void *)sock);
        err = CNL_STATUS_SUCCESS;

FREE_RULE:
        rtnl_rule_put(rule);
        nl_addr_put(src);
        nl_addr_put(dst);
FREE_CACHE:
        nl_cache_free(rule_cache);

FREE_SOCKET:
        nl_socket_free(sock);

        free(str);
        return err;
}

/**
 * tunnel_add_ip4ip6
 *  @tunnel_name: Tunnel interface name
 *  @dev_name: Device name
 *  @local_ip6: Local ipv6 address
 *  @remote_ip6: Remote ipv6 address
 *  @encaplimit: Encapsulation max size
 * Add ip4ip6 tunnel interface
 */
libnet_status tunnel_add_ip4ip6(const char *tunnel_name, const char *dev_name,
                                const char *local_ip6, const char *remote_ip6,
                                const char *encaplimit)
{
        struct nl_cache *link_cache;
        struct rtnl_link *link;
        struct in6_addr addr;
        struct nl_sock *sk;
        int if_index;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        if_index = rtnl_link_name2i(link_cache, dev_name);
        if (!if_index) {
                CNL_LOG_ERROR("Unable to lookup %s\n", dev_name);
                goto FREE_CACHE;
        }

        link = rtnl_link_ip6_tnl_alloc();
        if(!link) {
                CNL_LOG_ERROR("Unable to allocate link\n");
                goto FREE_CACHE;
        }

        rtnl_link_set_name(link, tunnel_name);
        ret = rtnl_link_ip6_tnl_set_link(link, if_index);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set tunnel interface index: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK;
        }

        if (inet_pton(AF_INET6, local_ip6, &addr) != 1) {
                // inet_pton returns failure if retVal is not 1
                CNL_LOG_ERROR("Invalid local IPV6 address\n");
                goto FREE_LINK;
        }

        ret = rtnl_link_ip6_tnl_set_local(link, &addr);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set tunnel local address: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK;
        }

        if (inet_pton(AF_INET6, remote_ip6, &addr) != 1) {
                // inet_pton returns failure if retVal is not 1
                CNL_LOG_ERROR("Invalid remote IPV6 address\n");
                goto FREE_LINK;
        }

        ret = rtnl_link_ip6_tnl_set_remote(link, &addr);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set tunnel remote address: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK;
        }

        ret = rtnl_link_add(sk, link, NLM_F_CREATE | NLM_F_EXCL);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to add link: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;

FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * interface_delete
 * @name: interface name
 *
 * Delete an interface
 */
libnet_status interface_delete(char *name)
{
        struct rtnl_link *link;
        struct nl_sock *sk;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link = rtnl_link_alloc();
        rtnl_link_set_name(link, name);

        int ret = rtnl_link_delete(sk, link);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to delete link: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK;
        }
        err = CNL_STATUS_SUCCESS;

FREE_LINK:
        rtnl_link_put(link);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * interface_set_flags
 * @if_name: interface name
 * @flags: netdevice flags
 *
 * Set interface flags
 */
libnet_status interface_set_flags(char *if_name, unsigned int flags)
{
        struct nl_sock *sk;
        struct rtnl_link *link;
        struct rtnl_link *change;
        struct nl_cache *cache;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        if (!(link = rtnl_link_get_by_name(cache, if_name))) {
                CNL_LOG_ERROR("Link not found\n");
                goto FREE_CACHE;
        }

        change = rtnl_link_alloc();
        rtnl_link_set_flags(change, flags);

        ret = rtnl_link_change(sk, link, change, 0);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to set flag: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK2;
        }
        err = CNL_STATUS_SUCCESS;

FREE_LINK2:
        rtnl_link_put(change);
FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(cache);
FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * interface_rename
 * @if_name: interface name
 * @new_name: netdevice flags
 *
 * Rename interface
 * This operation is not recommended if the device is running or
 * has some addresses already configured.
 */
libnet_status interface_rename(char *if_name, char *new_name)
{
        struct nl_sock *sk;
        struct rtnl_link *link;
        struct rtnl_link *change;
        struct nl_cache *cache;
        libnet_status err = CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        int ret = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to allocate cache: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_SOCKET;
        }

        if (!(link = rtnl_link_get_by_name(cache, if_name))) {
                CNL_LOG_ERROR("Interface not found\n");
                goto FREE_CACHE;
        }

        change = rtnl_link_alloc();
        rtnl_link_set_name(change, new_name);

        ret = rtnl_link_change(sk, link, change, 0);
        if (ret < 0) {
                CNL_LOG_ERROR("Unable to change name: %s (err=%d)\n",
                        nl_geterror(ret), ret);
                goto FREE_LINK2;
        }
        err = CNL_STATUS_SUCCESS;

FREE_LINK2:
        rtnl_link_put(change);
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(cache);
FREE_SOCKET:
        nl_socket_free(sk);
        return err;
}

/**
 * neighbour_delete
 * @dev: interface name
 * @ip: ip address
 *
 * Delete an entry in neighbour table
 */
libnet_status neighbour_delete(char *dev, char *ip)
{
        struct nl_sock *sock;
        struct rtnl_neigh *neigh;
        struct nl_cache *link_cache;
        libnet_status err = CNL_STATUS_FAILURE;

        sock = libnet_alloc_socket();

        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        link_cache = libnet_link_alloc_cache(sock);
        neigh = libnet_neigh_alloc();

        if (libnet_neigh_parse_dev(neigh, link_cache, dev) != 0) {
                CNL_LOG_ERROR("Unable to parse dev field\n");
                goto FREE_CACHE;
        }

        if (libnet_neigh_parse_dst(neigh, ip) != 0) {
                CNL_LOG_ERROR("Unable to parse dst field\n");
                goto FREE_CACHE;
        }

        if (rtnl_neigh_delete(sock, neigh, 0) < 0) {
                CNL_LOG_ERROR("Unable to delete neighbour\n");
                goto FREE_CACHE;
        }
        err = CNL_STATUS_SUCCESS;

FREE_CACHE:
        rtnl_neigh_put(neigh);
        nl_cache_put(link_cache);

FREE_SOCKET:
        nl_socket_free(sock);

        return err;
}

static void bridge_get_slave_name_cb(struct nl_object *match, void *arg)
{
        uint32_t ifindex;
        struct bridge_info *bridge = arg;
        char name[IFNAMSIZ] = {0};

        ifindex = rtnl_link_get_ifindex((struct rtnl_link *)match);
        if (0 >= ifindex)
                return;
        if (!rtnl_link_i2name(bridge->link_cache, ifindex, name, sizeof(name)))
                CNL_LOG_ERROR("Interface index %d does not exist\n",
                              ifindex);
        bridge->slave_name[bridge->slave_count++] = strdup(name);
}

/**
 * bridge_get_info
 * @bridge_name: bridge interface name
 * @bridge: bridge structure to fill
 * Get bridge details
 */
libnet_status bridge_get_info(char *bridge_name, struct bridge_info *bridge)
{
        struct nl_sock *sk;
        struct nl_cache *link_cache;
        struct rtnl_link *link;
        uint32_t ifindex;
        libnet_status err = CNL_STATUS_FAILURE;
        errno_t rc = -1;

        rc = memset_s(bridge, sizeof(struct bridge_info), 0, sizeof(struct bridge_info));
        ERR_CHK(rc);
        if (rc < EOK)
                return CNL_STATUS_FAILURE;

        sk = libnet_alloc_socket();
        if (sk == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache) < 0) {
                CNL_LOG_ERROR("Unable to allocate cache\n");
                goto FREE_SOCKET;
        }

        if (!(ifindex = rtnl_link_name2i(link_cache, bridge_name))) {
                CNL_LOG_ERROR("Interface %s does not exist\n", bridge_name);
                goto FREE_CACHE;
        }

        link = rtnl_link_alloc();
        rtnl_link_set_master(link, ifindex);

        bridge->link_cache = link_cache;
        nl_cache_foreach_filter(link_cache, OBJ_CAST(link), bridge_get_slave_name_cb,
                                (void *)bridge);

        rtnl_link_put(link);
        err = CNL_STATUS_SUCCESS;
FREE_CACHE:
        nl_cache_free(link_cache);
        bridge->link_cache = NULL;

FREE_SOCKET:
        nl_socket_free(sk);

        return err;
}

/**
 * bridge_free_info
 * @bridge: bridge_info memory to free
 * Free bridge_info members
 */
void bridge_free_info(struct bridge_info *bridge)
{
        while (0 != bridge->slave_count) {
                free(bridge->slave_name[bridge->slave_count-1]);
                bridge->slave_name[bridge->slave_count-1] = NULL;
                bridge->slave_count--;
        }
}

// Helper function: Allocate and initialize a neighbour_info structure.
struct neighbour_info* init_neighbour_info(void) {
        struct neighbour_info *nei_info = (struct neighbour_info*)calloc(1, sizeof(struct neighbour_info));
        if (!nei_info) {
            CNL_LOG_ERROR("Failed to allocate memory for neighbour_info\n");
            return NULL;
        }
        nei_info->neigh_count = 0;
        nei_info->neigh_capacity = INITIAL_NEIGH_CAPACITY;
        nei_info->neigh_arr = (struct _neighbour_info*)calloc(nei_info->neigh_capacity, sizeof(struct _neighbour_info));
        if (!nei_info->neigh_arr) {
            CNL_LOG_ERROR("Failed to allocate memory for neighbor array\n");
            free(nei_info);
            return NULL;
        }
        return nei_info;
    }

static void neighbour_get_cb(struct nl_object *match, void *arg)
{
        struct neighbour_cb_data *cb_data = arg;
        struct neighbour_info *neigh_info = cb_data->neigh_info;
        struct nl_sock *sock = cb_data->sock;
        char buf[40] = {0};

        // Extract the local address.
        const struct nl_addr *local_addr = rtnl_addr_get_local((struct rtnl_addr *) match);
        // If a filter is set, skip entries that do not match the address family.
        if (cb_data->af_filter != 0 && local_addr) {
                if (nl_addr_get_family(local_addr) != cb_data->af_filter)
                return;
        }

        // Check if the current capacity is reached; if so, expand the array.
        if (neigh_info->neigh_count >= neigh_info->neigh_capacity) {
                int new_capacity = (neigh_info->neigh_capacity > 0) ? (neigh_info->neigh_capacity * 2) : INITIAL_NEIGH_CAPACITY;
                struct _neighbour_info *new_neigh_arr = realloc(neigh_info->neigh_arr, new_capacity * sizeof(struct _neighbour_info));
                if (!new_neigh_arr) {
                        // Log the error and abort processing this neighbor.
                        CNL_LOG_ERROR("Memory allocation error while expanding neighbor array\n");
                        return;
                }
                // Optionally initialize the new memory to zero.
                memset(new_neigh_arr + neigh_info->neigh_capacity, 0, (new_capacity - neigh_info->neigh_capacity) * sizeof(struct _neighbour_info));
                neigh_info->neigh_arr = new_neigh_arr;
                neigh_info->neigh_capacity = new_capacity;
        }

        nl_addr2str(local_addr, buf, sizeof(buf));
        neigh_info->neigh_arr[neigh_info->neigh_count].local = strdup(buf);

        nl_addr2str(rtnl_neigh_get_lladdr((struct rtnl_neigh *) match), buf, sizeof(buf));
        neigh_info->neigh_arr[neigh_info->neigh_count].mac = strdup(buf);

        // Fetch the interface index and retrieve the interface name
        int ifindex = rtnl_neigh_get_ifindex((struct rtnl_neigh *) match);
        // Allocate a link cache using the socket
        struct nl_cache *link_cache;
        if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache) < 0) {
                CNL_LOG_ERROR("Unable to allocate rtnl link cache\n");
        }
        struct rtnl_link *link = rtnl_link_get(link_cache, ifindex);
        if (link) {
                const char *ifname = rtnl_link_get_name(link);
                neigh_info->neigh_arr[neigh_info->neigh_count].ifname = strdup(ifname);
                rtnl_link_put(link);
        }
        nl_cache_free(link_cache); // Ensure cache is freed

        int state = rtnl_neigh_get_state((struct rtnl_neigh *) match);

        // Filter out entries with NONE / NOARP / NUD_PERMANENT
        // NUD_NOARP and NUD_PERMANENT are pseudostates
        if (state == NUD_NONE || state == NUD_NOARP || state == NUD_PERMANENT) {
                if (neigh_info->neigh_arr[neigh_info->neigh_count].local != NULL) {
                        free(neigh_info->neigh_arr[neigh_info->neigh_count].local);
                        neigh_info->neigh_arr[neigh_info->neigh_count].local = NULL;
                }

                if (neigh_info->neigh_arr[neigh_info->neigh_count].mac != NULL) {
                        free(neigh_info->neigh_arr[neigh_info->neigh_count].mac);
                        neigh_info->neigh_arr[neigh_info->neigh_count].mac = NULL;
                }

                if (neigh_info->neigh_arr[neigh_info->neigh_count].ifname != NULL) {
                        free(neigh_info->neigh_arr[neigh_info->neigh_count].ifname);
                        neigh_info->neigh_arr[neigh_info->neigh_count].ifname = NULL;
                }

                return;
        }

        neigh_info->neigh_arr[neigh_info->neigh_count].state = state;

        neigh_info->neigh_count++;

}

/**
 * neighbour_get_list - lists all entries except for NONE, NOARP and NUD_PERMANENT
 * @arr: array to fill neighbour table
 * @mac: Optional MAC Filter. NULL if no filtering required
 * @if_name: Optional Interface name filter. If no interface filtering is desired, NULL
 * @af_filter: Pass 0 for the af_filter if no IP family filtering is desired. AF_INET- IPv4, AF_INET6 - IPv6
 * Get bridge details
 */
libnet_status neighbour_get_list(struct neighbour_info *arr, char *mac, char *if_name, int af_filter)
{
        struct nl_sock *sock;
        struct rtnl_neigh *neigh;
        struct nl_cache *neigh_cache;
        struct nl_addr *nl_mac_addr = NULL;
        libnet_status err = CNL_STATUS_FAILURE;

        sock = libnet_alloc_socket();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }
        if (libnet_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        neigh_cache = libnet_neigh_alloc_cache(sock);

        neigh = libnet_neigh_alloc();
        // If a valid MAC is provided, convert and set it in filter object "neigh"
        if (mac != NULL) {
                unsigned char mac_addr[6];
                if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &mac_addr[0], &mac_addr[1], &mac_addr[2],
                        &mac_addr[3], &mac_addr[4], &mac_addr[5]) == 6) {
                    nl_mac_addr = nl_addr_build(AF_LLC, mac_addr, sizeof(mac_addr));
                    if (nl_mac_addr != NULL) {
                        rtnl_neigh_set_lladdr(neigh, nl_mac_addr);
                    } else {
                        CNL_LOG_ERROR("Failed to create nl_addr object\n");
                    }
                } else {
                    CNL_LOG_ERROR("Invalid MAC address format\n");
                }
            }
        // Filter by interface name if provided
        if (if_name != NULL) {
                int ifindex = if_nametoindex(if_name);
                if (ifindex > 0) {
                    rtnl_neigh_set_ifindex(neigh, ifindex);
                } else {
                    CNL_LOG_ERROR("Invalid interface name: %s\n", if_name);
                }
        }
        struct neighbour_cb_data cb_data = { .neigh_info = arr, .sock = sock, .af_filter = af_filter };

        nl_cache_foreach_filter(neigh_cache, OBJ_CAST(neigh),
                                neighbour_get_cb, (void *)&cb_data);
        if (nl_mac_addr)
                nl_addr_put(nl_mac_addr);
        rtnl_neigh_put(neigh);
        nl_cache_put(neigh_cache);
        err = CNL_STATUS_SUCCESS;
FREE_SOCKET:
        nl_socket_free(sock);

        return err;
}

/**
 * neighbour_free_neigh
 * @neigh_info: neighbour table structure
 * Free neighbour_info members
 */
void neighbour_free_neigh(struct neighbour_info *neigh_info)
{
        while (0 != neigh_info->neigh_count) {
                free(neigh_info->neigh_arr[neigh_info->neigh_count-1].local);
                neigh_info->neigh_arr[neigh_info->neigh_count-1].local = NULL;

                free(neigh_info->neigh_arr[neigh_info->neigh_count-1].mac);
                neigh_info->neigh_arr[neigh_info->neigh_count-1].mac = NULL;

                free(neigh_info->neigh_arr[neigh_info->neigh_count-1].ifname);
                neigh_info->neigh_arr[neigh_info->neigh_count-1].ifname = NULL;

                neigh_info->neigh_count--;
        }
        free(neigh_info->neigh_arr);
        free(neigh_info);
}

/**
 * interface_get_stats
 * @ifStatsMask: Get the interface needed information by bitmask
 * @if_name: Name of the interface for information
 * @stats: Structure for interface stats
 *
 * Added for getting interface statistics
 */
libnet_status interface_get_stats(cnl_ifstats_mask ifstats_mask, const char* if_name, cnl_iface_stats *stats)
{
        struct nl_sock *sock;
        struct nl_cache *link_cache;
        struct rtnl_link *link;
        libnet_status err = CNL_STATUS_FAILURE;

        sock = nl_socket_alloc();
        if (sock == NULL) {
                CNL_LOG_ERROR("Unable to allocate memory for socket\n");
                return err;
        }

        if (nl_connect(sock, NETLINK_ROUTE) < 0) {
                CNL_LOG_ERROR("Unable to connect socket\n");
                goto FREE_SOCKET;
        }

        if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &link_cache) < 0) {
                CNL_LOG_ERROR("Unable to allocate cache\n");
                goto FREE_SOCKET;
        }

        link = rtnl_link_get_by_name(link_cache, if_name);
        if (!link) {
                CNL_LOG_ERROR("Unable to find the interface %s\n", if_name);
                goto FREE_CACHE;
        }

        if ((ifstats_mask & IFSTAT_RXTX_PACKET))
        {
                stats->rx_packet = rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS);
                stats->tx_packet = rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS);
                err = CNL_STATUS_SUCCESS;
        }

        if ((ifstats_mask & IFSTAT_RXTX_BYTES))
        {
                stats->rx_bytes = rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES);
                stats->tx_bytes = rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES);
                err = CNL_STATUS_SUCCESS;
        }

        if ((ifstats_mask & IFSTAT_RXTX_ERRORS))
        {
                stats->rx_errors = rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS);
                stats->tx_errors = rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS);
                err = CNL_STATUS_SUCCESS;
        }

        if ((ifstats_mask & IFSTAT_RXTX_DROPPED))
        {
                stats->rx_dropped = rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED);
                stats->tx_dropped = rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED);
                err = CNL_STATUS_SUCCESS;
        }

FREE_LINK:
        rtnl_link_put(link);
FREE_CACHE:
        nl_cache_free(link_cache);
FREE_SOCKET:
        nl_socket_free(sock);

        return err;
}

/**
 * interface_status
 * @if_name: interface name
 * @status: pointer to an integer to store the status (1 for UP, 0 for DOWN)
 *
 * Get the current status of the network interface.
 *
 * This function checks if the specified network interface is UP or DOWN
 * using the Netlink API. It sets the status to 1 if the interface is UP,
 * and 0 if the interface is DOWN.
 *
 * Returns:
 * CNL_STATUS_SUCCESS on success, or CNL_STATUS_FAILURE on error.
 */
libnet_status interface_status(char *if_name, int *status)
{
    struct nl_sock *sk;
    struct rtnl_link *link;
    struct nl_cache *cache;
    libnet_status err = CNL_STATUS_FAILURE;

    sk = libnet_alloc_socket();
    if (sk == NULL) {
        CNL_LOG_ERROR("Unable to allocate memory for socket\n");
        return err;
    }

    if (libnet_connect(sk, NETLINK_ROUTE) < 0) {
        CNL_LOG_ERROR("Unable to connect socket\n");
        goto FREE_SOCKET;
    }

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache) < 0) {
        CNL_LOG_ERROR("Unable to allocate cache\n");
        goto FREE_SOCKET;
    }

    if (!(link = rtnl_link_get_by_name(cache, if_name))) {
        CNL_LOG_ERROR("Interface not found\n");
        goto FREE_CACHE;
    }

    unsigned int flags = rtnl_link_get_flags(link);
    *status = (flags & IFF_UP) ? 1 : 0;

    err = CNL_STATUS_SUCCESS;

    rtnl_link_put(link);
FREE_CACHE:
    nl_cache_free(cache);
FREE_SOCKET:
    nl_socket_free(sk);

    return err;
}

int is_global_ipv6(struct rtnl_addr *addr) {
    return rtnl_addr_get_scope(addr) == RT_SCOPE_UNIVERSE;
}

void store_global_ipv6_address(struct nl_object *obj, void *arg) {
    struct callback_data *data = (struct callback_data *)arg;
    if (data->found) {
        return; // Stop further processing if a global address is already found
    }

    struct rtnl_addr *addr = (struct rtnl_addr *)obj;
    struct nl_addr *local = rtnl_addr_get_local(addr);
    if (local && nl_addr_get_family(local) == AF_INET6) {
        char buf[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, nl_addr_get_binary_addr(local), buf, sizeof(buf));

        if (is_global_ipv6(addr)) {
            strncpy(data->ipv6_addr, buf, INET6_ADDRSTRLEN);
            data->ipv6_addr[INET6_ADDRSTRLEN - 1] = '\0'; // Ensure null-termination
            data->found = 1; // Set the flag to indicate a global address is found
        }
    }
}

/**
 * get_ipv6_address
 * @if_name: interface name
 * @ipv6_addr: pointer to a buffer to store the IPv6 address
 * @addr_len: length of the buffer
 *
 * Get the global IPv6 address of the network interface.
 *
 * This function retrieves the global IPv6 address of the specified network interface
 * using the Netlink API. It stores the address in the provided buffer if a global
 * IPv6 address is found.
 *
 * Returns:
 * CNL_STATUS_SUCCESS on success, or CNL_STATUS_FAILURE on error or if no global IPv6 address is found.
 */
libnet_status get_ipv6_address(char *if_name, char *ipv6_addr, size_t addr_len) {
    struct nl_sock *sk;
    struct rtnl_link *link;
    struct nl_cache *link_cache, *addr_cache;
    libnet_status err = CNL_STATUS_FAILURE;

    // Validate addr_len
    if (addr_len < INET6_ADDRSTRLEN) {
        CNL_LOG_ERROR("Buffer size is too small for an IPv6 address");
        return err;
    }

    // Allocate memory if ipv6_addr is NULL
    char *allocated_addr = NULL;
    if (ipv6_addr == NULL) {
        allocated_addr = (char *)malloc(INET6_ADDRSTRLEN);
        if (allocated_addr == NULL) {
            CNL_LOG_ERROR("Unable to allocate memory for IPv6 address");
            return err;
        }
        ipv6_addr = allocated_addr;
    }

    sk = nl_socket_alloc();
    if (sk == NULL) {
        CNL_LOG_ERROR("Unable to allocate memory for socket");
        goto FREE_ALLOCATED_ADDR;
    }

    if (nl_connect(sk, NETLINK_ROUTE) < 0) {
        CNL_LOG_ERROR("Unable to connect socket");
        goto FREE_SOCKET;
    }

    if (rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache) < 0) {
        CNL_LOG_ERROR("Unable to allocate link cache");
        goto FREE_SOCKET;
    }

    link = rtnl_link_get_by_name(link_cache, if_name);
    if (!link) {
        CNL_LOG_ERROR("Interface not found");
        goto FREE_LINK_CACHE;
    }

    if (rtnl_addr_alloc_cache(sk, &addr_cache) < 0) {
        CNL_LOG_ERROR("Unable to allocate address cache");
        goto FREE_LINK;
    }

    struct callback_data data = { .ipv6_addr = ipv6_addr, .found = 0 };
    nl_cache_foreach(addr_cache, store_global_ipv6_address, &data);

    if (data.found) {
        err = CNL_STATUS_SUCCESS;
    }

    nl_cache_free(addr_cache);
FREE_LINK:
    rtnl_link_put(link);
FREE_LINK_CACHE:
    nl_cache_free(link_cache);
FREE_SOCKET:
    nl_socket_free(sk);
FREE_ALLOCATED_ADDR:
    if (err != CNL_STATUS_SUCCESS && allocated_addr) {
        free(allocated_addr);
        *ipv6_addr = NULL;
    }

    return err;
}
