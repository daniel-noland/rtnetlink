// SPDX-License-Identifier: MIT

use std::convert::TryInto;
use std::process::Command;

use futures::stream::TryStreamExt;
use netlink_packet_core::ErrorMessage;
use netlink_packet_route::tc::filters::ethernet::{EthType, VlanId, VlanPrio};
use netlink_packet_route::tc::{
    arp, icmpv4, icmpv6, TcAction, TcActionAttribute, TcActionGeneric,
    TcActionMirror, TcActionMirrorOption, TcActionOption, TcActionTunnelKey,
    TcActionTunnelKeyOption, TcActionType, TcFilterFlowerOption,
    TcFilterU32Option, TcFlowerOptionFlags, TcMirror, TcMirrorActionType,
    TcTunnelKeyAction, TcTunnelParams, TcU32Key, TcU32Selector,
    TcU32SelectorFlags, TcpFlags,
};
use netlink_packet_route::{
    tc::{TcAttribute, TcMessage},
    AddressFamily, EncKeyId, IpProtocol, RouteNetlinkMessage,
    RouteNetlinkMessageBuffer,
};
use netlink_packet_utils::{Parseable, ParseableParametrized};
use nix::libc::{RTM_GETACTION, RTM_NEWACTION};
use tokio::runtime::Runtime;

use crate::{new_connection, Error::NetlinkError};

static TEST_DUMMY_NIC: &str = "netlink-test";

async fn _get_qdiscs() -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut qdiscs_iter = handle.qdisc().get().execute();
    let mut qdiscs = Vec::new();
    while let Some(nl_msg) = qdiscs_iter.try_next().await.unwrap() {
        qdiscs.push(nl_msg.clone());
    }
    qdiscs
}

#[test]
fn test_create_u32_redirect() {
    let rt = Runtime::new().unwrap();
    async fn _create_u32_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 18;
        handle
            .traffic_filter(dst_index)
            .add()
            .ingress()
            .priority(1000)
            .index(dst_index)
            .redirect(dst_index as u32)
            .unwrap()
            .execute()
            .await
            .unwrap()
    }
    rt.block_on(_create_u32_filter());
}

#[test]
fn test_create_u32_filter() {
    let rt = Runtime::new().unwrap();
    async fn _create_u32_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 18;
        let mut sel_na = TcU32Selector::default();
        sel_na.flags = TcU32SelectorFlags::Terminal;
        sel_na.nkeys = 1;
        sel_na.keys = vec![TcU32Key::default()];
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = dst_index;
        let mut action_nla = TcAction::default();
        action_nla.attributes = vec![
            TcActionAttribute::Kind(TcActionMirror::KIND.to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Mirror(
                TcActionMirrorOption::Parms(tc_mirror_nla),
            )]),
        ];
        let u32_nla = vec![
            TcFilterU32Option::Selector(sel_na),
            TcFilterU32Option::Action(vec![action_nla]),
        ];
        handle
            .traffic_filter(dst_index as i32)
            .add()
            .index(dst_index as i32)
            .priority(1002)
            .ingress()
            .u32(&u32_nla)
            .unwrap()
            .execute()
            .await
            .unwrap()
    }
    rt.block_on(_create_u32_filter());
}

#[test]
fn test_create_flower_filter_sctp() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 22;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::ClassId(1.into()),
                TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                TcFilterFlowerOption::KeyEthDstMask([
                    0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
                ]),
                TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyIpProto(IpProtocol::Sctp),
                TcFilterFlowerOption::KeyIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4SrcMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEncIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4SrcMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(1000)),
                TcFilterFlowerOption::KeySctpSrcMask(0x00ff),
                TcFilterFlowerOption::KeySctpDstMask(0x0a0a),
                TcFilterFlowerOption::KeySctpSrc(80),
                TcFilterFlowerOption::KeySctpDst(88),
                TcFilterFlowerOption::KeyEncUdpSrcPort(4789),
                TcFilterFlowerOption::KeyEncUdpSrcPortMask(0x0b0b),
                TcFilterFlowerOption::KeyEncUdpDstPort(4789),
                TcFilterFlowerOption::KeyEncUdpDstPortMask(0xa0a0),
                // TcFilterFlowerOption::FlowerKeyFlags(FlowerKeyFlags::TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT | FlowerKeyFlags::TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter_arp() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 22;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::ClassId(1.into()),
                TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                TcFilterFlowerOption::KeyEthDstMask([
                    0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
                ]),
                TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                TcFilterFlowerOption::KeyEthType(EthType::Arp),
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEncIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4SrcMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(1000)),
                TcFilterFlowerOption::KeyEncUdpSrcPort(4789),
                TcFilterFlowerOption::KeyEncUdpSrcPortMask(0x0b0b),
                TcFilterFlowerOption::KeyEncUdpDstPort(4789),
                TcFilterFlowerOption::KeyEncUdpDstPortMask(0xa0a0),
                TcFilterFlowerOption::KeyArpOp(arp::Operation::Request),
                TcFilterFlowerOption::KeyArpOpMask(0xab),
                TcFilterFlowerOption::KeyArpSha([1, 2, 3, 4, 5, 6]),
                TcFilterFlowerOption::KeyArpShaMask([7, 8, 9, 0xa, 0xb, 0xc]),
                TcFilterFlowerOption::KeyArpTha(
                    [6, 5, 4, 3, 2, 1].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyArpThaMask(
                    [0xc, 0xb, 0xa, 9, 8, 7].try_into().unwrap(),
                ),
                // TcFilterFlowerOption::FlowerKeyFlags(FlowerKeyFlags::TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT | FlowerKeyFlags::TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 22;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::ClassId(1.into()),
                TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                TcFilterFlowerOption::KeyEthDstMask([
                    0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
                ]),
                TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyIpProto(IpProtocol::Icmp),
                TcFilterFlowerOption::KeyIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4SrcMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEncIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4SrcMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(1000)),
                TcFilterFlowerOption::KeyIcmpv4Code(icmpv4::Code::EchoRequest(
                    icmpv4::EchoRequest::NoCode,
                )),
                TcFilterFlowerOption::KeyIcmpv4CodeMask(0xab),
                TcFilterFlowerOption::KeyIcmpv4Type(icmpv4::Type::EchoReply),
                TcFilterFlowerOption::KeyIcmpv4TypeMask(0xcd),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter6() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 23;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 23; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::Vlan.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::ClassId(2.into()),
                TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                TcFilterFlowerOption::KeyEthDstMask([
                    0xFF, 0xFF, 0xFF, 0xFF, 0, 0,
                ]),
                TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                TcFilterFlowerOption::KeyEthType(EthType::Vlan),
                // TcFilterFlowerOption::KeyIpProto(IpProtocol::Icmp),
                TcFilterFlowerOption::KeyIpv6Src(
                    [
                        0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv6SrcMask(
                    [
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv6Dst(
                    [
                        0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv6DstMask(
                    [
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                // TcFilterFlowerOption::KeyTcpSrc(80),
                // TcFilterFlowerOption::KeyTcpDst(88),
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyVlanEthType(EthType::IPv6),
                // TcFilterFlowerOption::KeyIpProto(IpProtocol::Icmp),
                TcFilterFlowerOption::KeyVlanId(VlanId::try_new(11).unwrap()),
                TcFilterFlowerOption::KeyVlanPrio(
                    VlanPrio::try_new(3).unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv6Dst(
                    [
                        0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv6DstMask(
                    [
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv6Src(
                    [
                        0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv6SrcMask(
                    [
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0,
                    ]
                    .try_into()
                    .unwrap(),
                ),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(2000)),
                // TcFilterFlowerOption::KeyTcpSrcMask(0x00ff),
                // TcFilterFlowerOption::KeyTcpDstMask(0x0a0a),
                TcFilterFlowerOption::KeyIcmpv6Code(1),
                TcFilterFlowerOption::KeyIcmpv6CodeMask(0xac),
                TcFilterFlowerOption::KeyIcmpv6Type(
                    icmpv6::Type::DestinationUnreachable,
                ),
                TcFilterFlowerOption::KeyIcmpv6TypeMask(0xde),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter_mpls() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 23;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 23; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::MplsUnicast.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::MplsUnicast),
                TcFilterFlowerOption::KeyMplsTtl(64),
                TcFilterFlowerOption::KeyMplsTc(0x2),
                TcFilterFlowerOption::KeyMplsBos(0x1),
                TcFilterFlowerOption::KeyMplsLabel(100),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter_tcp_flags() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 23;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 23; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyIpProto(IpProtocol::Tcp),
                TcFilterFlowerOption::KeyTcpFlags(TcpFlags::Syn),
                TcFilterFlowerOption::KeyTcpFlagsMask(0xab),
                TcFilterFlowerOption::KeyIpTos(0x2),
                TcFilterFlowerOption::KeyIpTtl(64),
                TcFilterFlowerOption::KeyIpTtlMask(0xa0),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter_cvlan() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 23;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 23; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(dst_index)
            .priority(1009)
            .protocol(EthType::Qinq.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::Qinq),
                TcFilterFlowerOption::KeyVlanId(VlanId::try_new(11).unwrap()),
                TcFilterFlowerOption::KeyVlanEthType(EthType::Vlan),
                TcFilterFlowerOption::KeyVlanPrio(
                    VlanPrio::try_new(3).unwrap(),
                ),
                TcFilterFlowerOption::KeyCvlanEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyCvlanId(VlanId::try_new(12).unwrap()),
                TcFilterFlowerOption::KeyCvlanPrio(
                    VlanPrio::try_new(4).unwrap(),
                ),
                TcFilterFlowerOption::KeyIpProto(IpProtocol::Tcp),
                TcFilterFlowerOption::KeyTcpFlags(TcpFlags::Syn),
                TcFilterFlowerOption::KeyTcpFlagsMask(0xab),
                TcFilterFlowerOption::KeyIpTos(0x2),
                TcFilterFlowerOption::KeyIpTtl(64),
                TcFilterFlowerOption::KeyIpTtlMask(0xa0),
                TcFilterFlowerOption::KeyEncIpTtl(64),
                TcFilterFlowerOption::KeyEncIpTtlMask(0xa0),
                TcFilterFlowerOption::KeyEncIpTos(0x2),
                TcFilterFlowerOption::KeyEncIpTosMask(0x0f),
                TcFilterFlowerOption::Action(vec![acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_geneve_opts() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 21;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.index = 1;
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        let mut acts2 = TcAction::default();
        let mut tc_tunnel_key = TcTunnelParams::default();
        tc_tunnel_key.generic = TcActionGeneric::default();
        tc_tunnel_key.generic.index = 1;
        tc_tunnel_key.generic.action = TcActionType::Pipe;
        tc_tunnel_key.tunnel_key_action = TcTunnelKeyAction::Set;
        acts2
            .attributes
            .push(TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()));
        acts2.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Params(
                tc_tunnel_key,
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncKeyId(
                EncKeyId::new(1000),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncIpv4Dst(
                [192, 168, 1, 0].try_into().unwrap(),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncIpv4Src(
                [192, 168, 1, 0].try_into().unwrap(),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncTtl(64)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyNoChecksum(
                true,
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncTos(0x2)),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(17)
            .priority(1007)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                // TcFilterFlowerOption::KeyEncOpts(EncOpts::Geneve(vec![
                //     GeneveEncOpts::Class(GeneveClass::new(0x1)).into(),
                //     GeneveEncOpts::Type(GeneveType::new(0x2)).into(),
                //     GeneveEncOpts::Data(GeneveData::new(vec![
                //         0x3456
                //     ]))
                //     .into(),
                // ])),
                // TcFilterFlowerOption::KeyEncOptsMask(EncOpts::Geneve(vec![
                //     GeneveEncOpts::Class(GeneveClass::new(0x1)).into(),
                //     GeneveEncOpts::Type(GeneveType::new(0x2)).into(),
                //     GeneveEncOpts::Data(GeneveData::new(vec![
                //         0x3456
                //     ]))
                //         .into(),
                // ])),
                TcFilterFlowerOption::Action(vec![acts2, acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_tunnel_key_unset() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 17;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        // tc_mirror_nla.generic.index = 1;
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        let mut acts2 = TcAction::default();
        let mut tc_tunnel_key = TcTunnelParams::default();
        tc_tunnel_key.generic = TcActionGeneric::default();
        // tc_tunnel_key.generic.index = 1;
        tc_tunnel_key.generic.action = TcActionType::Pipe;
        tc_tunnel_key.tunnel_key_action = TcTunnelKeyAction::Release;
        acts2
            .attributes
            .push(TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()));
        acts2.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Params(
                tc_tunnel_key,
            )),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(22)
            .priority(1007)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(1000)),
                TcFilterFlowerOption::KeyEncIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncUdpDstPort(4789),
                // TcFilterFlowerOption::KeyEncUdpSrcPort(4789),
                TcFilterFlowerOption::KeyEncIpTtl(64),
                TcFilterFlowerOption::KeyEncIpTos(0x2),
                TcFilterFlowerOption::Action(vec![acts2, acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_fancy_actions() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 17;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        // tc_mirror_nla.generic.index = 1;
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 22; // dest index
        let mut acts = TcAction::default();
        acts.attributes
            .push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::Mirror(TcActionMirrorOption::Parms(tc_mirror_nla)),
        ]));
        let mut acts2 = TcAction::default();
        let mut tc_tunnel_key = TcTunnelParams::default();
        tc_tunnel_key.generic = TcActionGeneric::default();
        // tc_tunnel_key.generic.index = 1;
        tc_tunnel_key.generic.action = TcActionType::Pipe;
        tc_tunnel_key.tunnel_key_action = TcTunnelKeyAction::Release;
        acts2
            .attributes
            .push(TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()));
        acts2.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Params(
                tc_tunnel_key,
            )),
        ]));
        handle
            .traffic_filter(dst_index)
            .add()
            .index(22)
            .priority(1007)
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyEncKeyId(EncKeyId::new(1000)),
                TcFilterFlowerOption::KeyEncIpv4Dst(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncIpv4Src(
                    [192, 168, 1, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyEncUdpDstPort(4789),
                // TcFilterFlowerOption::KeyEncUdpSrcPort(4789),
                TcFilterFlowerOption::KeyEncIpTtl(64),
                TcFilterFlowerOption::KeyEncIpTos(0x2),
                TcFilterFlowerOption::Action(vec![acts2, acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_filter(dst_index).get();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_get_actions() {
    async fn _test_get_actions() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let mut get = handle
            .traffic_action()
            .get()
            .kind("mirred".to_string())
            .execute();
        while let Some(msg) = get.try_next().await.unwrap() {
            println!("biscuits: {msg:?}");
        }
    }
    let rt = Runtime::new().unwrap();
    rt.block_on(_test_get_actions());
}

#[test]
fn test_get_actions_tunnel_key() {
    async fn _test_get_actions() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let mut get = handle
            .traffic_action()
            .get()
            .kind("tunnel_key".to_string())
            .execute();
        while let Some(msg) = get.try_next().await.unwrap() {
            println!("biscuits: {msg:?}");
        }
    }
    let rt = Runtime::new().unwrap();
    rt.block_on(_test_get_actions());
}

#[test]
fn test_add_action_recorded_correct() {
    let buf = hex::decode("0000000068000100640001000f00010074756e6e656c5f6b657900005000028008000700000003e808000300c0a8016208000400c0a8016305000d004000000005000c000200000005000a00010000001c000200630000000000000003000000000000000000000001000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_NEWACTION).unwrap();
    println!("{:?}", parsed);
}

#[test]
fn test_add_action_recorded_incorrect() {
    let buf = hex::decode("0000000088000100840001000f00010074756e6e656c5f6b65790000500002001c00020063000000000000000300000000000000000000000100000008000700000003e808000400c0a8016208000300c0a8016305000d004000000005000a000100000005000c0002000000200002001c0002000000000000000000ffffffff000000000000000001000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_NEWACTION).unwrap();
    println!("{:?}", parsed);

}

#[test]
fn test_add_action_tunnel_key() {
    async fn _add_action_tunnel_key() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let mut action = TcAction::default();
        let mut tc_tunnel_key = TcTunnelParams::default();
        tc_tunnel_key.generic = TcActionGeneric::default();
        tc_tunnel_key.generic.index = 102;
        tc_tunnel_key.generic.action = TcActionType::Pipe;
        tc_tunnel_key.tunnel_key_action = TcTunnelKeyAction::Set;
        action
            .attributes
            .push(TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()));
        action.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Params(
                tc_tunnel_key,
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncKeyId(
                EncKeyId::new(1000),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncIpv4Dst(
                [192, 168, 1, 97].try_into().unwrap(),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncIpv4Src(
                [192, 168, 1, 99].try_into().unwrap(),
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncTtl(64)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyNoChecksum(
                true,
            )),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::KeyEncTos(0x2)),
        ]));
        let mut resp = handle
            .traffic_action()
            .add()
            .action(action)
            .execute()
            .await;
        while let Some(msg) = resp.try_next().await.unwrap() {
            println!("biscuits: {msg:?}");
        }
    }
    let rt = Runtime::new().unwrap();
    rt.block_on(_add_action_tunnel_key());
}

#[test]
fn del_action_tunnel_key() {
    async fn _del_action_tunnel_key() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let mut action = TcAction::default();
        action
            .attributes
            .push(TcActionAttribute::Kind(TcActionTunnelKey::KIND.to_string()));
        action
            .attributes
            .push(TcActionAttribute::Index(102));
        handle
            .traffic_action()
            .del()
            .action(action)
            .execute()
            .await
            .unwrap();
    }
    let rt = Runtime::new().unwrap();
    rt.block_on(_del_action_tunnel_key());
}

#[test]
fn test_list_actions_buffer() {
    let buf = hex::decode("0000000018000100140001000f00010074756e6e656c5f6b657900000c0002000100000001000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_GETACTION).unwrap();
    println!("{:?}", parsed);
}

#[test]
fn test_list_actions_buffer2() {
    let buf = hex::decode("0000000018000100140001000f00010074756e6e656c5f6b657900000c0002000100000001000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_GETACTION).unwrap();
    println!("{:?}", parsed);
}

#[test]
fn test_list_actions_buffer3() {
    let buf = hex::decode("0300000014020100b00000000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000100000000000000040000000100000000000000010000000a00000024000100f44a000000000000f44a00000000000000000000000000000000000000000000b00001000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000200000000000000040000000100000000000000010000000a000000240001001a410000000000001a4100000000000000000000000000000000000000000000b00002000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000300000000000000040000000100000000000000010000000100000024000100e702000000000000e70200000000000000000000000000000000000000000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_GETACTION).unwrap();
    println!("{parsed:?}");
}

#[test]
fn test_list_actions_buffer4() {
    let buf = hex::decode("0300000014020100b00000000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000100000000000000040000000100000000000000010000000a00000024000100f44a000000000000f44a00000000000000000000000000000000000000000000b00001000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000200000000000000040000000100000000000000010000000a000000240001001a410000000000001a4100000000000000000000000000000000000000000000b00002000b0001006d6972726564000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a000000000048000200200002000300000000000000040000000100000000000000010000000100000024000100e702000000000000e70200000000000000000000000000000000000000000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    // let parsed = NetlinkMessage::parse(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_GETACTION).unwrap();
    println!("{:?}", parsed);
}

#[test]
fn test_list_actions_tunnel_key() {
    let buf = hex::decode("030000008c020100d80000000f00010074756e6e656c5f6b6579000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a00000000006c0002001c00020001000000000000000300000001000000000000000100000008000700000003e808000300ac12010108000400ac1201020600090012b5000005000a0001000000240001007c0f0000000000007c0f00000000000000000000000000000000000000000000d80001000f00010074756e6e656c5f6b6579000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a00000000006c0002001c00020002000000000000000300000001000000000000000100000008000700000007d008000300ac12010108000400ac1201030600090012b5000005000a000100000024000100210d000000000000210d00000000000000000000000000000000000000000000d80002000f00010074756e6e656c5f6b6579000044000400140001000000000000000000000000000000000014000700000000000000000000000000000000001800030000000000000000000000000000000000000000000c000900000000000300000008000a00000000006c0002001c0002000300000000000000030000000100000000000000010000000800070000000bb808000300ac12010108000400ac1201040600090012b5000005000a0001000000240001006d0a0000000000006d0a00000000000000000000000000000000000000000000").unwrap();
    let buf = RouteNetlinkMessageBuffer::new(&buf);
    let parsed =
        RouteNetlinkMessage::parse_with_param(&buf, RTM_GETACTION).unwrap();
    println!("{:?}", parsed);
}

// #[test]
// fn test_create_list_actions() {
//     let rt = Runtime::new().unwrap();
//     async fn _list_actions() {
//         let (connection, handle, _) = new_connection().unwrap();
//         tokio::spawn(connection);
//         let mut get = handle.traffic_action().get().action("mirred".to_string()).execute();
//         while let Some(msg) = get.try_next().await.unwrap() {
//             println!("biscuits: {:?}", msg);
//         }
//     }
//     rt.block_on(_list_actions())
// }

#[test]
fn test_create_fancy_chain() {
    let rt = Runtime::new().unwrap();
    async fn _create_fancy_chain() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 21;
        handle
            .traffic_chain(dst_index)
            .add()
            .ingress()
            .index(dst_index)
            // .priority(1007)
            .chain(23)
            .unwrap()
            .protocol(EthType::IPv4.as_u16().to_be())
            .ingress()
            .flower(&[
                // TcFilterFlowerOption::Flags(TcFlowerOptionFlags::SkipHw),
                TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                TcFilterFlowerOption::KeyIpv4Dst(
                    [192, 168, 0, 0].try_into().unwrap(),
                ),
                TcFilterFlowerOption::KeyIpv4DstMask(
                    [255, 255, 255, 0].try_into().unwrap(),
                ),
                // TcFilterFlowerOption::KeyEncOpts(EncOpts::Geneve(vec![
                //     GeneveEncOpts::Class(GeneveClass::new(0x1)).into(),
                //     GeneveEncOpts::Type(GeneveType::new(0x2)).into(),
                //     GeneveEncOpts::Data(GeneveData::new(vec![
                //         0x3456
                //     ]))
                //     .into(),
                // ])),
                // TcFilterFlowerOption::KeyEncOptsMask(EncOpts::Geneve(vec![
                //     GeneveEncOpts::Class(GeneveClass::new(0x1)).into(),
                //     GeneveEncOpts::Type(GeneveType::new(0x2)).into(),
                //     GeneveEncOpts::Data(GeneveData::new(vec![
                //         0x3456
                //     ]))
                //         .into(),
                // ])),
                // TcFilterFlowerOption::Action(vec![acts2, acts]),
            ])
            .unwrap()
            .execute()
            .await
            .unwrap();
        let mut get = handle.traffic_chain(dst_index).get().ingress();
        let mut get2 = get.execute();
        let mut get3 = get2;
        while let Some(msg) = get3.try_next().await.unwrap() {
            println!("biscuits: {:?}", msg);
        }
    }
    rt.block_on(_create_fancy_chain())
}

#[test]
fn test_get_qdiscs() {
    let qdiscs = Runtime::new().unwrap().block_on(_get_qdiscs());
    let qdisc_of_loopback_nic = &qdiscs[0];
    assert_eq!(qdisc_of_loopback_nic.header.family, AddressFamily::Unspec);
    assert_eq!(qdisc_of_loopback_nic.header.index, 1);
    assert_eq!(qdisc_of_loopback_nic.header.handle, 0.into());
    assert_eq!(qdisc_of_loopback_nic.header.parent, u32::MAX.into());
    assert_eq!(qdisc_of_loopback_nic.header.info, 2); // refcount
    assert_eq!(
        qdisc_of_loopback_nic.attributes[0],
        TcAttribute::Kind("noqueue".to_string())
    );
    assert_eq!(
        qdisc_of_loopback_nic.attributes[1],
        TcAttribute::HwOffload(0)
    );
}

async fn _get_tclasses(ifindex: i32) -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut tclasses_iter = handle.traffic_class(ifindex).get().execute();
    let mut tclasses = Vec::new();
    while let Some(nl_msg) = tclasses_iter.try_next().await.unwrap() {
        tclasses.push(nl_msg.clone());
    }
    tclasses
}

// Return 0 for not found
fn _get_test_dummy_interface_index() -> i32 {
    let output = Command::new("ip")
        .args(["-o", "link", "show", TEST_DUMMY_NIC])
        .output()
        .expect("failed to run ip command");
    if !output.status.success() {
        0
    } else {
        let line = std::str::from_utf8(&output.stdout).unwrap();
        line.split(": ").next().unwrap().parse::<i32>().unwrap()
    }
}

fn _add_test_dummy_interface() -> i32 {
    if _get_test_dummy_interface_index() == 0 {
        let output = Command::new("ip")
            .args(["link", "add", TEST_DUMMY_NIC, "type", "dummy"])
            .output()
            .expect("failed to run ip command");
        if !output.status.success() {
            eprintln!(
                "Failed to create dummy interface {TEST_DUMMY_NIC} : {output:?}"
            );
        }
        assert!(output.status.success());
    }

    _get_test_dummy_interface_index()
}

fn _remove_test_dummy_interface() {
    let output = Command::new("ip")
        .args(["link", "del", TEST_DUMMY_NIC])
        .output()
        .expect("failed to run ip command");
    if !output.status.success() {
        eprintln!(
            "Failed to remove dummy interface {TEST_DUMMY_NIC} : {output:?}"
        );
    }
    assert!(output.status.success());
}

fn _add_test_tclass_to_dummy() {
    let output = Command::new("tc")
        .args([
            "qdisc",
            "add",
            "dev",
            TEST_DUMMY_NIC,
            "root",
            "handle",
            "1:",
            "htb",
            "default",
            "6",
        ])
        .output()
        .expect("failed to run tc command");
    if !output.status.success() {
        eprintln!(
            "Failed to add qdisc to dummy interface {TEST_DUMMY_NIC} : {output:?}"
        );
    }
    assert!(output.status.success());
    let output = Command::new("tc")
        .args([
            "class",
            "add",
            "dev",
            TEST_DUMMY_NIC,
            "parent",
            "1:",
            "classid",
            "1:1",
            "htb",
            "rate",
            "10mbit",
            "ceil",
            "10mbit",
        ])
        .output()
        .expect("failed to run tc command");
    if !output.status.success() {
        eprintln!(
            "Failed to add traffic class to dummy interface {TEST_DUMMY_NIC}: {output:?}"
        );
    }
    assert!(output.status.success());
}

fn _add_test_filter_to_dummy() {
    let output = Command::new("tc")
        .args([
            "filter",
            "add",
            "dev",
            TEST_DUMMY_NIC,
            "parent",
            "1:",
            "basic",
            "match",
            "meta(priority eq 6)",
            "classid",
            "1:1",
        ])
        .output()
        .expect("failed to run tc command");
    if !output.status.success() {
        eprintln!("Failed to add trafice filter to lo: {output:?}");
    }
    assert!(output.status.success());
}

fn _remove_test_tclass_from_dummy() {
    Command::new("tc")
        .args([
            "class",
            "del",
            "dev",
            TEST_DUMMY_NIC,
            "parent",
            "1:",
            "classid",
            "1:1",
        ])
        .status()
        .unwrap_or_else(|_| {
            panic!(
                "failed to remove tclass from dummy interface {}",
                TEST_DUMMY_NIC
            )
        });
    Command::new("tc")
        .args(["qdisc", "del", "dev", TEST_DUMMY_NIC, "root"])
        .status()
        .unwrap_or_else(|_| {
            panic!(
                "failed to remove qdisc from dummy interface {}",
                TEST_DUMMY_NIC
            )
        });
}

fn _remove_test_filter_from_dummy() {
    Command::new("tc")
        .args(["filter", "del", "dev", TEST_DUMMY_NIC])
        .status()
        .unwrap_or_else(|_| {
            panic!(
                "failed to remove filter from dummy interface {}",
                TEST_DUMMY_NIC
            )
        });
}

async fn _get_filters(ifindex: i32) -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut filters_iter = handle.traffic_filter(ifindex).get().execute();
    let mut filters = Vec::new();
    while let Some(nl_msg) = filters_iter.try_next().await.unwrap() {
        filters.push(nl_msg.clone());
    }
    filters
}

async fn _get_chains(ifindex: i32) -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut chains_iter = handle.traffic_chain(ifindex).get().execute();
    let mut chains = Vec::new();
    // The traffic control chain is only supported by kernel 4.19+,
    // hence we might get error: 95 Operation not supported
    loop {
        match chains_iter.try_next().await {
            Ok(Some(nl_msg)) => {
                chains.push(nl_msg.clone());
            }
            Ok(None) => {
                break;
            }
            Err(NetlinkError(ErrorMessage {
                code, header: _, ..
            })) => {
                assert_eq!(code, std::num::NonZeroI32::new(-95));
                eprintln!(
                    "The chain in traffic control is not supported, \
                     please upgrade your kernel"
                );
            }
            _ => {}
        }
    }
    chains
}

// The `cargo test` by default run all tests in parallel, in stead
// of create random named veth/dummy for test, just place class, filter, and
// chain query test in one test case is much simpler.
#[test]
#[cfg_attr(not(feature = "test_as_root"), ignore)]
fn test_get_traffic_classes_filters_and_chains() {
    let ifindex = _add_test_dummy_interface();
    _add_test_tclass_to_dummy();
    _add_test_filter_to_dummy();
    let tclasses = Runtime::new().unwrap().block_on(_get_tclasses(ifindex));
    let filters = Runtime::new().unwrap().block_on(_get_filters(ifindex));
    let chains = Runtime::new().unwrap().block_on(_get_chains(ifindex));
    _remove_test_filter_from_dummy();
    _remove_test_tclass_from_dummy();
    _remove_test_dummy_interface();
    assert_eq!(tclasses.len(), 1);
    let tclass = &tclasses[0];
    assert_eq!(tclass.header.family, AddressFamily::Unspec);
    assert_eq!(tclass.header.index, ifindex);
    assert_eq!(tclass.header.parent, u32::MAX.into());
    assert_eq!(tclass.attributes[0], TcAttribute::Kind("htb".to_string()));
    assert_eq!(filters.len(), 2);
    assert_eq!(filters[0].header.family, AddressFamily::Unspec);
    assert_eq!(filters[0].header.index, ifindex);
    assert_eq!(filters[0].header.parent, (u16::MAX as u32 + 1).into());
    assert_eq!(
        filters[0].attributes[0],
        TcAttribute::Kind("basic".to_string())
    );
    assert_eq!(filters[1].header.family, AddressFamily::Unspec);
    assert_eq!(filters[1].header.index, ifindex);
    assert_eq!(filters[1].header.parent, (u16::MAX as u32 + 1).into());
    assert_eq!(
        filters[1].attributes[0],
        TcAttribute::Kind("basic".to_string())
    );
    assert!(chains.len() <= 1);
    if chains.len() == 1 {
        assert_eq!(chains[0].header.family, AddressFamily::Unspec);
        assert_eq!(chains[0].header.index, ifindex);
        assert_eq!(chains[0].header.parent, (u16::MAX as u32 + 1).into());
        assert_eq!(chains[0].attributes[0], TcAttribute::Chain(0),);
    }
}
