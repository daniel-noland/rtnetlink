// SPDX-License-Identifier: MIT

use std::convert::TryInto;
use std::process::Command;

use futures::stream::TryStreamExt;
use netlink_packet_core::ErrorMessage;
use netlink_packet_route::{AddressFamily, IpProtocol, tc::{TcAttribute, TcMessage}};
use netlink_packet_route::tc::{EthType, TcAction, TcActionAttribute, TcActionGeneric, TcActionMirror, TcActionMirrorOption, TcActionOption, TcActionType, TcFilterFlowerOption, TcFilterU32Option, TcMirror, TcMirrorActionType, TcU32Key, TcU32Selector, TcU32SelectorFlags};
use tokio::runtime::Runtime;

use crate::{Error::NetlinkError, new_connection};

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
fn test_create_flower_filter() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 18;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 18; // dest index
        let mut acts = TcAction::default();
        acts.attributes.push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![TcActionOption::Mirror(
            TcActionMirrorOption::Parms(tc_mirror_nla),
        )]));
        handle.traffic_filter(dst_index)
              .add()
              .index(dst_index)
              .priority(1009)
              .ingress()
              .flower(&[
                  TcFilterFlowerOption::ClassId(1.into()),
                  TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                  TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                  TcFilterFlowerOption::KeyEthDstMask([0xFF, 0xFF, 0xFF, 0xFF, 0, 0]),
                  TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                  TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                  TcFilterFlowerOption::KeyEthType(EthType::IPv4),
                  TcFilterFlowerOption::KeyIpProto(IpProtocol::Ah),
                  TcFilterFlowerOption::KeyIpv4Src([192, 168, 1, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv4SrcMask([255, 255, 255, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv4Dst([192, 168, 1, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv4DstMask([255, 255, 255, 0].try_into().unwrap()),
                  TcFilterFlowerOption::Flags(0x1),
                  TcFilterFlowerOption::Action(vec![acts]),
              ])
              .unwrap()
              .execute()
              .await
              .unwrap()
    }
    rt.block_on(_create_flower_filter())
}

#[test]
fn test_create_flower_filter6() {
    let rt = Runtime::new().unwrap();
    async fn _create_flower_filter() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let dst_index = 18;
        let mut tc_mirror_nla = TcMirror::default();
        tc_mirror_nla.generic = TcActionGeneric::default();
        tc_mirror_nla.generic.action = TcActionType::Stolen;
        tc_mirror_nla.eaction = TcMirrorActionType::EgressRedir;
        tc_mirror_nla.ifindex = 18; // dest index
        let mut acts = TcAction::default();
        acts.attributes.push(TcActionAttribute::Kind(TcActionMirror::KIND.to_string()));
        acts.attributes.push(TcActionAttribute::Options(vec![TcActionOption::Mirror(
            TcActionMirrorOption::Parms(tc_mirror_nla),
        )]));
        handle.traffic_filter(dst_index)
              .add()
              .index(dst_index)
              .priority(1009)
              .ingress()
              .flower(&[
                  TcFilterFlowerOption::ClassId(1.into()),
                  TcFilterFlowerOption::Indev("x".as_bytes().to_vec()),
                  TcFilterFlowerOption::KeyEthDst([0xde, 0xad, 0xbe, 0xef, 0, 0]),
                  TcFilterFlowerOption::KeyEthDstMask([0xFF, 0xFF, 0xFF, 0xFF, 0, 0]),
                  TcFilterFlowerOption::KeyEthSrc([1, 2, 3, 4, 5, 6]),
                  TcFilterFlowerOption::KeyEthSrcMask([7, 8, 9, 0xa, 0xb, 0xc]),
                  TcFilterFlowerOption::KeyEthType(EthType::IPv6),
                  TcFilterFlowerOption::KeyIpProto(IpProtocol::Tcp),
                  TcFilterFlowerOption::KeyIpv6Src([0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv6SrcMask([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv6Dst([0xfe, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyIpv6DstMask([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].try_into().unwrap()),
                  TcFilterFlowerOption::KeyTcpSrc(80),
                  TcFilterFlowerOption::KeyTcpDst(88),
                  TcFilterFlowerOption::Action(vec![acts]),
              ])
              .unwrap()
              .execute()
              .await
              .unwrap()
    }
    rt.block_on(_create_flower_filter())
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
