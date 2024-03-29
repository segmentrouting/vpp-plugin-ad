/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_srv6_ad_h__
#define __included_srv6_ad_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/srv6/sr_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define DA_IP4 4
#define DA_IP6 6

typedef struct {
  u16 msg_id_base;                        /**< API message ID base */

  vlib_main_t * vlib_main;                /**< [convenience] vlib main */
  vnet_main_t * vnet_main;                /**< [convenience] vnet main */

  dpo_type_t srv6_ad_dpo_type;            /**< DPO type */

  u32 srv6_localsid_behavior_id;          /**< SRv6 LocalSID behavior number */

  u32 *         sw_iface_localsid4;       /**< Retrieve local SID from iface */
  u32 *         sw_iface_localsid6;       /**< Retrieve local SID from iface */
} srv6_ad_main_t;

/*
 * This is the memory that will be stored per each localsid
 * the user instantiates
 */
typedef struct {
	ip46_address_t	nh_addr;                  /**< Proxied device address */
  u32				sw_if_index_out;	            /**< Outgoing iface to proxied dev. */
  u32				nh_adj;				                /**< Adjacency index for out. iface */
	u8				ip_version;

  u32				sw_if_index_in;		            /**< Incoming iface from proxied dev. */
  u8 *			rewrite;			                /**< Headers to be rewritten */
} srv6_ad_localsid_t ;

srv6_ad_main_t srv6_ad_main;

format_function_t format_srv6_ad_localsid;
unformat_function_t unformat_srv6_ad_localsid;

void srv6_ad_dpo_lock (dpo_id_t * dpo);
void srv6_ad_dpo_unlock (dpo_id_t * dpo);

extern vlib_node_registration_t srv6_ad_localsid_node;

#endif /* __included_srv6_ad_h__ */
