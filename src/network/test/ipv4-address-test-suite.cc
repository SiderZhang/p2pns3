/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/test.h"
#include "ns3/ipv4-address.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace ns3;
using namespace std;

class Ipv4AddressTestCase1 : public TestCase
{
public:
  Ipv4AddressTestCase1 ();
  virtual ~Ipv4AddressTestCase1 ();

private:
  virtual void DoRun (void);
};

Ipv4AddressTestCase1::Ipv4AddressTestCase1 ()
  : TestCase ("serialization code")
{
}

Ipv4AddressTestCase1::~Ipv4AddressTestCase1 ()
{
}

void
Ipv4AddressTestCase1::DoRun (void)
{
    Ipv4Address ip;
    uint32_t code = 192;
    ip.DeserialFromInt(code);
    uint8_t buf[4];
    memset (buf, 0, 4);
    ip.Serialize(buf);
    uint32_t result = ip.Serial2Int();
    
    buf[0] = (code >> 24) & 0xff;
    buf[1] = (code >> 16) & 0xff;
    buf[2] = (code >> 8) & 0xff;
    buf[3] = (code >> 0) & 0xff;

    char temp[256];
    memset (temp, 0, 256);
    sprintf (temp, "%d %d; %d %d %d %d", code, result, buf[0], buf[1], buf[2], buf[3]);

    NS_TEST_ASSERT_MSG_EQ (code, result, temp);
}

class Ipv4AddressTestSuite : public TestSuite
{
public:
  Ipv4AddressTestSuite ();
};

Ipv4AddressTestSuite::Ipv4AddressTestSuite ()
  : TestSuite ("ipv4-address", UNIT)
{
  AddTestCase (new Ipv4AddressTestCase1, TestCase::QUICK);
}

static Ipv4AddressTestSuite ipv6AddressTestSuite;

