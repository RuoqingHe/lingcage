// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Frames between a guest and a smoltcp interface, queued both ways. The
//! stack and the metadata service drive smoltcp through it.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as Tick;

/// smoltcp `Device` over two queues; `Net` fills `from_guest` and drains
/// `to_guest`.
pub(crate) struct Pipe {
    pub(crate) from_guest: VecDeque<Vec<u8>>,
    pub(crate) to_guest: VecDeque<Vec<u8>>,
    pub(crate) mtu: usize,
}

/// One frame from the guest, handed to smoltcp.
pub(crate) struct FromGuest(Vec<u8>);

impl RxToken for FromGuest {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

/// Room for one frame to the guest, filled by smoltcp.
pub(crate) struct ToGuest<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for ToGuest<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0u8; len];
        let done = f(&mut frame);
        self.0.push_back(frame);
        done
    }
}

impl Device for Pipe {
    type RxToken<'a>
        = FromGuest
    where
        Self: 'a;
    type TxToken<'a>
        = ToGuest<'a>
    where
        Self: 'a;

    fn receive(&mut self, _now: Tick) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.from_guest.pop_front()?;
        Some((FromGuest(frame), ToGuest(&mut self.to_guest)))
    }

    fn transmit(&mut self, _now: Tick) -> Option<Self::TxToken<'_>> {
        Some(ToGuest(&mut self.to_guest))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
