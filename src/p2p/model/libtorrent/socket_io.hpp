/*

Copyright (c) 2009, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef TORRENT_SOCKET_IO_HPP_INCLUDED
#define TORRENT_SOCKET_IO_HPP_INCLUDED

#include "ns3/libtorrent/socket.hpp"
#include "ns3/libtorrent/io.hpp"
#include "ns3/libtorrent/error_code.hpp"
#include "ns3/libtorrent/lazy_entry.hpp"
#include "ns3/libtorrent/peer_id.hpp" // for sha1_hash
#include <string>

#include "ns3/address.h"
#include "ns3/ipv4-end-point.h"

namespace libtorrent
{
	TORRENT_EXPORT std::string print_address(ns3::Address const& addr);
	TORRENT_EXPORT std::string print_endpoint(ns3::Ipv4EndPoint const& ep);
	TORRENT_EXPORT std::string print_endpoint(ns3::Ipv4EndPoint const& ep);
	TORRENT_EXPORT std::string address_to_bytes(ns3::Address const& a);
	TORRENT_EXPORT std::string endpoint_to_bytes(ns3::Ipv4EndPoint const& ep);
	void hash_address(ns3::Address const& ip, sha1_hash& h);

//	namespace detail
//	{
//		template<class OutIt>
//		void write_address(address const& a, OutIt& out)
//		{
//			write_uint32(a.to_v4().to_ulong(), out);
//		}
//
//		template<class InIt>
//		address read_v4_address(InIt& in)
//		{
//			unsigned long ip = read_uint32(in);
//			return address_v4(ip);
//		}
//
//		template<class Endpoint, class OutIt>
//		void write_endpoint(Endpoint const& e, OutIt& out)
//		{
//			write_address(e.address(), out);
//			write_uint16(e.port(), out);
//		}
//
//	//	template<class Endpoint, class InIt>
//	//	Endpoint read_v4_endpoint(InIt& in)
//	//	{
//	//		address addr = read_v4_address(in);
//	//		int port = read_uint16(in);
////	//		return Endpoint(addr, port);
//	//	}
//
//		template <class EndpointType>
//		void read_endpoint_list(libtorrent::lazy_entry const* n, std::vector<EndpointType>& epl)
//		{
////			using namespace libtorrent;
////			if (n->type() != lazy_entry::list_t) return;
////			for (int i = 0; i < n->list_size(); ++i)
////			{
////				lazy_entry const* e = n->list_at(i);
////				if (e->type() != lazy_entry::string_t) return;
////				if (e->string_length() < 6) continue;
////				char const* in = e->string_ptr();
////				if (e->string_length() == 6)
////					epl.push_back(read_v4_endpoint<EndpointType>(in));
////			}
//		}
//
//	}


}

#endif

