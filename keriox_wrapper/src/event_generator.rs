use crate::{entity::Key, error::Error};
use keri::{
    derivation::self_addressing::SelfAddressing,
    event::sections::seal::{DigestSeal, Seal},
    event_message::event_msg_builder::{EventMsgBuilder, EventType},
    prefix::{IdentifierPrefix},
    state::IdentifierState,
};


    pub fn make_icp(
        pk: &Key,
        nxt_pk: &Key,
        prefix: Option<IdentifierPrefix>,
    ) -> Result<(IdentifierPrefix, Vec<u8>), Error> {
        let pref = prefix.unwrap_or(IdentifierPrefix::default());
        let key_prefix = vec![pk.derive_key_prefix()];
        let nxt_key_prefix = vec![nxt_pk.derive_key_prefix()];
        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_prefix(pref)
            .with_keys(key_prefix)
            .with_next_keys(nxt_key_prefix)
            .build()?;
        Ok((icp.event.prefix.clone(), icp.serialize()?))
    }

    pub fn make_rot(
        pk: &Key,
        nxt_pk: &Key,
        state: IdentifierState,
    ) -> Result<Vec<u8>, Error> {
        let key_prefix = vec![pk.derive_key_prefix()];
        let nxt_key_prefix = vec![nxt_pk.derive_key_prefix()];
        let ixn = EventMsgBuilder::new(EventType::Rotation)?
            .with_prefix(state.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_keys(key_prefix)
            .with_next_keys(nxt_key_prefix)
            .build()?
            .serialize()?;
        Ok(ixn)
    }

    pub fn make_ixn(
        payload: Option<&str>,
        state: IdentifierState,
    ) -> Result<Vec<u8>, Error> {
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };
        let ev = EventMsgBuilder::new(EventType::Interaction)?
            .with_prefix(state.prefix.clone())
            .with_sn(state.sn + 1)
            .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
            .with_seal(seal_list)
            .build()?;
        Ok(ev.serialize()?)
    }