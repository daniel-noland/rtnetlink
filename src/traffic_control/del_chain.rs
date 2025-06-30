// SPDX-License-Identifier: MIT

use crate::{try_nl, Error, Handle};
use futures::stream::StreamExt;
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_route::tc::{TcAttribute, TcHeader};
use netlink_packet_route::{
    tc::{TcHandle, TcMessage},
    RouteNetlinkMessage,
};

#[derive(Debug, Clone)]
pub struct TrafficChainDelRequest {
    handle: Handle,
    message: TcMessage,
    flags: u16,
}

impl TrafficChainDelRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32) -> Self {
        Self {
            handle,
            message: TcMessage::with_index(ifindex),
            flags: NLM_F_REQUEST | NLM_F_ACK,
        }
    }

    /// Set interface index.
    /// Equivalent to `dev STRING`, dev and block are mutually exlusive.
    pub fn index(mut self, index: i32) -> Self {
        self.message.header.index = index;
        self
    }

    /// Set block index.
    /// Equivalent to `block BLOCK_INDEX`.
    pub fn block(mut self, block_index: u32) -> Self {
        self.message.header.index = TcHeader::TCM_IFINDEX_MAGIC_BLOCK as i32;
        self.message.header.parent = block_index.into();
        self
    }

    pub fn chain(mut self, chain: u32) -> Self {
        self.message.attributes.push(TcAttribute::Chain(chain));
        self
    }

    /// Set parent qdisc
    pub fn parent(mut self, parent: TcHandle) -> Self {
        self.message.header.parent = parent;
        self
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut handle,
            message,
            flags,
        } = self;

        let mut req =
            NetlinkMessage::from(RouteNetlinkMessage::DelTrafficChain(message));
        req.header.flags = flags;

        let mut response = handle.request(req)?;
        if let Some(message) = response.next().await {
            try_nl!(message);
        }

        Ok(())
    }
}
