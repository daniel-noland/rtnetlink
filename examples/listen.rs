// SPDX-License-Identifier: MIT

//! This example opens a netlink socket, registers for IPv4 and IPv6 routing
//! changes, listens for said changes and prints the received messages.

use futures::stream::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_packet_route::neighbour::NeighbourMessage;
use netlink_sys::{AsyncSocket, SocketAddr};

use rtnetlink::constants::{RTMGRP_LINK, RTMGRP_NEIGH, RTMGRP_TC};
use rtnetlink::new_connection;

#[tokio::main]
async fn main() -> Result<(), String> {
    // Open the netlink socket
    let (mut connection, _, mut messages) =
        new_connection().map_err(|e| format!("{e}"))?;

    // These flags specify what kinds of broadcast messages we want to listen
    // for.
    let mgroup_flags = RTMGRP_NEIGH | RTMGRP_LINK | RTMGRP_TC;

    // A netlink socket address is created with said flags.
    let addr = SocketAddr::new(0, mgroup_flags);
    // Said address is bound so new connections and thus new message broadcasts
    // can be received.
    connection
        .socket_mut()
        .socket_mut()
        .bind(&addr)
        .expect("failed to bind");
    tokio::spawn(connection);

    while let Some((message, _)) = messages.next().await {
        let payload = message.payload;
        match payload {
            NetlinkPayload::Done(d) => {
                println!("Done - {d:?}");
            }
            NetlinkPayload::Error(e) => {
                println!("Error - {e:?}");
            }
            NetlinkPayload::Noop => {
                println!("Noop");
            }
            NetlinkPayload::Overrun(o) => {
                println!("Overrun - {o:?}");
            }
            NetlinkPayload::InnerMessage(m) => {
                match m {
                    RouteNetlinkMessage::NewLink(new_link) => {
                        println!("New link: {new_link:?}");
                    }
                    RouteNetlinkMessage::DelLink(del_link) => {
                        println!("Del link: {del_link:?}");
                    }
                    RouteNetlinkMessage::GetLink(get_link) => {
                        println!("Get link: {get_link:?}");
                    }
                    RouteNetlinkMessage::SetLink(set_link) => {
                        println!("Set link: {set_link:?}");
                    }
                    RouteNetlinkMessage::NewLinkProp(new_link_prop) => {
                        println!("New link prop: {new_link_prop:?}");
                    }
                    RouteNetlinkMessage::DelLinkProp(del_link_prop) => {
                        println!("Del link prop: {del_link_prop:?}");
                    }
                    RouteNetlinkMessage::NewAddress(_) => {}
                    RouteNetlinkMessage::DelAddress(_) => {}
                    RouteNetlinkMessage::GetAddress(_) => {}
                    RouteNetlinkMessage::NewNeighbour(new_neigh) => {
                        let NeighbourMessage { header, attributes, .. } = new_neigh;
                        if header.family != AddressFamily::Bridge {
                            continue;
                        }
                        println!("New neighbour: {attributes:?}");
                    }
                    RouteNetlinkMessage::GetNeighbour(_) => {}
                    RouteNetlinkMessage::DelNeighbour(del_neigh) => {
                        let NeighbourMessage { header, attributes, .. } = del_neigh;
                        if header.family != AddressFamily::Bridge {
                            continue;
                        }
                        println!("Del neighbour: {attributes:?}");
                    }
                    RouteNetlinkMessage::NewNeighbourTable(_) => {}
                    RouteNetlinkMessage::GetNeighbourTable(_) => {}
                    RouteNetlinkMessage::SetNeighbourTable(_) => {}
                    RouteNetlinkMessage::NewRoute(_) => {}
                    RouteNetlinkMessage::DelRoute(_) => {}
                    RouteNetlinkMessage::GetRoute(_) => {}
                    RouteNetlinkMessage::NewPrefix(_) => {}
                    RouteNetlinkMessage::NewQueueDiscipline(_) => {}
                    RouteNetlinkMessage::DelQueueDiscipline(_) => {}
                    RouteNetlinkMessage::GetQueueDiscipline(_) => {}
                    RouteNetlinkMessage::NewTrafficClass(_) => {}
                    RouteNetlinkMessage::DelTrafficClass(_) => {}
                    RouteNetlinkMessage::GetTrafficClass(_) => {}
                    RouteNetlinkMessage::NewTrafficFilter(filter) => {
                        println!("New traffic filter: {filter:?}");
                    }
                    RouteNetlinkMessage::DelTrafficFilter(filter) => {
                        println!("Del traffic filter: {filter:?}");
                    }
                    RouteNetlinkMessage::GetTrafficFilter(_) => {}
                    RouteNetlinkMessage::NewTrafficChain(_) => {}
                    RouteNetlinkMessage::DelTrafficChain(_) => {}
                    RouteNetlinkMessage::GetTrafficChain(_) => {}
                    RouteNetlinkMessage::NewNsId(_) => {}
                    RouteNetlinkMessage::DelNsId(_) => {}
                    RouteNetlinkMessage::GetNsId(_) => {}
                    RouteNetlinkMessage::NewRule(_) => {}
                    RouteNetlinkMessage::DelRule(_) => {}
                    RouteNetlinkMessage::GetRule(_) => {}
                    _ => { println!("Unhandled message - {m:?}"); }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
