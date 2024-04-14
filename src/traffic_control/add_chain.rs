// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_route::tc::{TcFilterFlower, TcFilterFlowerOption};
use netlink_packet_route::{
    tc::{
        TcAction, TcActionAttribute, TcActionGeneric, TcActionMirror,
        TcActionMirrorOption, TcActionOption, TcActionType, TcAttribute,
        TcFilterU32, TcFilterU32Option, TcHandle, TcHeader, TcMessage,
        TcMirror, TcMirrorActionType, TcOption, TcU32Key, TcU32Selector,
        TcU32SelectorFlags,
    },
    RouteNetlinkMessage,
};

use crate::{try_nl, Error, Handle};

pub struct TrafficChainNewRequest {
    handle: Handle,
    message: TcMessage,
    flags: u16,
}

impl TrafficChainNewRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32, flags: u16) -> Self {
        Self {
            handle,
            message: TcMessage::with_index(ifindex),
            flags: NLM_F_REQUEST | flags,
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(
            RouteNetlinkMessage::NewTrafficChain(message),
        );
        req.header.flags = NLM_F_ACK | flags;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
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

    /// Set parent.
    /// Equivalent to `[ root | ingress | egress | parent CLASSID ]`
    /// command args. They are mutually exclusive.
    pub fn parent(mut self, parent: u32) -> Self {
        self.message.header.parent = parent.into();
        self
    }

    /// Set parent to root.
    pub fn root(mut self) -> Self {
        self.message.header.parent = TcHandle::ROOT;
        self
    }

    /// Set parent to ingress.
    pub fn ingress(mut self) -> Self {
        self.message.header.parent = TcHandle {
            major: 0xffff,
            minor: TcHandle::MIN_INGRESS,
        };
        self
    }

    /// Set parent to egress.
    pub fn egress(mut self) -> Self {
        self.message.header.parent = TcHandle {
            major: 0xffff,
            minor: TcHandle::MIN_EGRESS,
        };
        self
    }

    /// Set protocol.
    /// Equivalent to `protocol PROT`.
    /// Default: ETH_P_ALL 0x0003, see llproto_names at iproute2/lib/ll_proto.c.
    pub fn protocol(mut self, protocol: u16) -> Self {
        self.message.header.info = u32::from(TcHandle {
            major: (self.message.header.info >> 16) as u16,
            minor: protocol,
        });
        self
    }

    /// The 32bit filter allows to match arbitrary bitfields in the packet.
    /// Equivalent to `tc filter ... u32`.
    pub fn u32(mut self, options: &[TcFilterU32Option]) -> Result<Self, Error> {
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
            .push(TcAttribute::Kind(TcFilterU32::KIND.to_string()));
        let mut nla_opts = Vec::new();
        for opt in options {
            nla_opts.push(TcOption::U32(opt.clone()));
        }
        self.message.attributes.push(TcAttribute::Options(nla_opts));
        Ok(self)
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

        let mut nla_opts = Vec::new();
        for opt in options {
            nla_opts.push(TcOption::Flower(opt.clone()));
        }
        self.message.attributes.push(TcAttribute::Options(nla_opts));
        Ok(self)
    }

    pub fn chain(mut self, chain: u32) -> Result<Self, Error> {
        if self.message.attributes.iter().any(|nla| matches!(nla, TcAttribute::Chain(_))) {
            return Err(Error::InvalidNla(
                "message chain has already been set.".to_string(),
            ));
        }
        self.message.attributes.push(TcAttribute::Chain(chain));
        Ok(self)
    }
}
