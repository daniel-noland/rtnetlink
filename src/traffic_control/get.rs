// SPDX-License-Identifier: MIT

use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};
use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_route::tc::{
    TcAction, TcActionAttribute, TcActionMessage, TcActionMessageFlags,
    TcActionMessageFlagsWithSelector, TcActionMessageNla, TcAttribute,
};
use netlink_packet_route::{
    tc::{TcHandle, TcMessage},
    AddressFamily, RouteNetlinkMessage,
};

use crate::{try_rtnl, Error, Handle};

pub struct QDiscGetRequest {
    handle: Handle,
    message: TcMessage,
}

impl QDiscGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        QDiscGetRequest {
            handle,
            message: TcMessage::default(),
        }
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = TcMessage, Error = Error> {
        let QDiscGetRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(
            RouteNetlinkMessage::GetQueueDiscipline(message),
        );
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                Ok(try_rtnl!(msg, RouteNetlinkMessage::NewQueueDiscipline))
            })),
            Err(e) => {
                Either::Right(future::err::<TcMessage, Error>(e).into_stream())
            }
        }
    }

    pub fn index(mut self, index: i32) -> Self {
        self.message.header.index = index;
        self
    }

    /// Get ingress qdisc
    pub fn ingress(mut self) -> Self {
        self.message.header.parent = TcHandle::INGRESS;
        self
    }
}

pub struct TrafficClassGetRequest {
    handle: Handle,
    message: TcMessage,
}

impl TrafficClassGetRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32) -> Self {
        let mut message = TcMessage::default();
        message.header.index = ifindex;
        TrafficClassGetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = TcMessage, Error = Error> {
        let TrafficClassGetRequest {
            mut handle,
            message,
        } = self;

        let mut req =
            NetlinkMessage::from(RouteNetlinkMessage::GetTrafficClass(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                Ok(try_rtnl!(msg, RouteNetlinkMessage::NewTrafficClass))
            })),
            Err(e) => {
                Either::Right(future::err::<TcMessage, Error>(e).into_stream())
            }
        }
    }
}

pub struct TrafficFilterGetRequest {
    handle: Handle,
    message: TcMessage,
}

impl TrafficFilterGetRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32) -> Self {
        let mut message = TcMessage::default();
        message.header.index = ifindex;
        message.header.handle = TcHandle { major: 0, minor: 0 };
        message.header.parent = TcHandle {
            major: 0xffff,
            minor: 0xfff2,
        };
        message.header.info = 0;
        message.header.family = AddressFamily::Unspec;
        TrafficFilterGetRequest { handle, message }
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = TcMessage, Error = Error> {
        let TrafficFilterGetRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(
            RouteNetlinkMessage::GetTrafficFilter(message),
        );
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                Ok(try_rtnl!(msg, RouteNetlinkMessage::NewTrafficFilter))
            })),
            Err(e) => {
                Either::Right(future::err::<TcMessage, Error>(e).into_stream())
            }
        }
    }

    /// Set parent to root.
    pub fn root(mut self) -> Self {
        self.message.header.parent = TcHandle::ROOT;
        self
    }

    /// Set parent to clsact ingress.
    pub fn clsact(mut self) -> Self {
        self.message.header.parent = TcHandle::CLSACT;
        self
    }
}

pub struct TrafficChainGetRequest {
    handle: Handle,
    message: TcMessage,
}

impl TrafficChainGetRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32) -> Self {
        let mut message = TcMessage::default();
        message.header.index = ifindex;
        TrafficChainGetRequest { handle, message }
    }

    pub fn ingress(mut self) -> Self {
        self.message.header.parent = TcHandle {
            major: u16::MAX,
            minor: TcHandle::MIN_INGRESS,
        };
        self
    }

    pub fn egress(mut self) -> Self {
        self.message.header.parent = TcHandle {
            major: u16::MAX,
            minor: TcHandle::MIN_EGRESS,
        };
        self
    }

    // TODO: add error handling
    pub fn chain_index(mut self, index: u32) -> Self {
        self.message.attributes.push(TcAttribute::Chain(index));
        // self.message.header.index = index;
        // self
        self
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = TcMessage, Error = Error> {
        let TrafficChainGetRequest {
            mut handle,
            message,
        } = self;

        let mut req =
            NetlinkMessage::from(RouteNetlinkMessage::GetTrafficChain(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                Ok(try_rtnl!(msg, RouteNetlinkMessage::NewTrafficChain))
            })),
            Err(e) => {
                Either::Right(future::err::<TcMessage, Error>(e).into_stream())
            }
        }
    }
}

pub struct TrafficActionGetRequest {
    handle: Handle,
    message: TcActionMessage,
}

impl TrafficActionGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        let mut message = TcActionMessage::default();
        message.header.family = AddressFamily::Unspec;
        Self { handle, message }
    }

    pub fn kind(mut self, action: String) -> Self {
        let kind = TcActionAttribute::Kind(action);
        let mut tc_action = TcAction::default();
        tc_action.attributes.push(kind);
        let acts = TcActionMessageNla::Actions(vec![tc_action]);
        self.message.attributes.push(acts);
        let flags = TcActionMessageNla::Flags(
            TcActionMessageFlagsWithSelector::new(TcActionMessageFlags::LargeDump)
        );
        self.message.attributes.push(flags);
        self
    }

    /// Execute the request
    pub fn execute(
        self,
    ) -> impl TryStream<Ok = TcActionMessage, Error = Error> {
        let Self {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(
            RouteNetlinkMessage::GetTrafficAction(message),
        );
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                Ok(try_rtnl!(msg, RouteNetlinkMessage::GetTrafficAction))
            })),
            Err(e) => Either::Right(
                future::err::<TcActionMessage, Error>(e).into_stream(),
            ),
        }
    }
}
