// SPDX-License-Identifier: MIT

use crate::{try_nl, Error, Handle};
use futures::StreamExt;
use netlink_packet_core::{
    NetlinkMessage, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::tc::{
    TcAttribute, TcFilterFlower, TcFilterFlowerOption, TcHandle, TcHeader,
    TcMessage, TcOption,
};
use netlink_packet_route::RouteNetlinkMessage;

pub struct TrafficChainNewRequest {
    handle: Handle,
    message: TcMessage,
    flags: u16,
}

impl TrafficChainNewRequest {
    pub fn new(handle: Handle, ifindex: i32) -> Self {
        Self {
            handle,
            message: TcMessage::with_index(ifindex),
            flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut handle,
            message,
            flags,
        } = self;

        let mut req =
            NetlinkMessage::from(RouteNetlinkMessage::NewTrafficChain(message));
        req.header.flags =
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE | flags;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    pub fn chain(mut self, chain: u32) -> Self {
        self.message.attributes.push(TcAttribute::Chain(chain));
        self
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

    pub fn flower(
        mut self,
        options: &[TcFilterFlowerOption],
    ) -> Result<Self, Error> {
        if self
            .message
            .attributes
            .iter()
            .any(|nla| matches!(nla, TcAttribute::Kind(_)))
        {
            return Err(Error::InvalidNla(
                "message kind has already been set.".to_string(),
            ));
        }
        self.message
            .attributes
            .push(TcAttribute::Kind(TcFilterFlower::KIND.to_string()));
        let nla_opts: Vec<_> = options
            .iter()
            .map(|opt| TcOption::Flower(opt.clone()))
            .collect();
        self.message.attributes.push(TcAttribute::Options(nla_opts));
        Ok(self)
    }

    /// Set parent to ingress.
    pub fn ingress(mut self) -> Self {
        self.message.header.parent = TcHandle {
            major: 0xffff,
            minor: TcHandle::MIN_INGRESS,
        };
        self
    }

    /// Set parent qdisc
    pub fn parent(mut self, parent: TcHandle) -> Self {
        self.message.header.parent = parent;
        self
    }
}
