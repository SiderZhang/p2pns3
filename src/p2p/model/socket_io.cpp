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

#include <string>

#include "libtorrent/escape_string.hpp"
#include "libtorrent/error_code.hpp"
#include "libtorrent/socket.hpp"
#include "libtorrent/socket_io.hpp"
#include "libtorrent/io.hpp" // for write_uint16
#include "libtorrent/hasher.hpp" // for hasher

#include <exception>

using namespace std;
using namespace ns3;

namespace libtorrent
{

	std::string print_address(Address const& addr)
	{
		error_code ec;
        throw exception();
//		return addr.to_string(ec);
	}

	std::string address_to_bytes(Address const& a)
	{
		std::string ret;
		std::back_insert_iterator<std::string> out(ret);
        throw exception();
//		detail::write_address(a, out);
//		return ret;
	}

	std::string endpoint_to_bytes(ns3::Ipv4EndPoint const& ep)
	{
		std::string ret;
		std::back_insert_iterator<std::string> out(ret);
        throw exception();
		//detail::write_endpoint(ep, out);
		//return ret;
	}

	std::string print_endpoint(Ipv4EndPoint const& ep)
	{
		error_code ec;
		std::string ret;
        throw exception();
//		address const& addr = ep.address();
//#if TORRENT_USE_IPV6
//		if (addr.is_v6())
//		{
//			ret += '[';
//			ret += addr.to_string(ec);
//			ret += ']';
//			ret += ':';
//			ret += to_string(ep.port()).elems;
//		}
//		else
//#endif
//		{
//			ret += addr.to_string(ec);
//			ret += ':';
//			ret += to_string(ep.port()).elems;
//		}
//		return ret;
	}

//	std::string print_endpoint(Ipv4EndPoint const& ep)
//	{
//        throw exception();
////		return print_endpoint(tcp::endpoint(ep.address(), ep.port()));
//	}

	void hash_address(Address const& ip, sha1_hash& h)
	{
        uint8_t buffer[20];
        uint32_t size = ip.CopyTo(buffer);
        h = hasher((char*)&buffer[0], size).final();
	}

}

