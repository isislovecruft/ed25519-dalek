
pub type Commitment = [u8; 64];

/// State machine structures for holding intermediate values during an aggregate
/// signing protocol run, to prevent misuse.
#[derive(Clone, Debug, PartialEq)]
pub enum AggregateSigning {
    Error,
    RoundOne(RoundOne),
    RoundTwo(RoundTwo),
    RoundThree(RoundThree),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoundOne {
    pub(crate) my_ephemeral_secret: Scalar,
    pub(crate) my_ephemeral_public: EdwardsPoint,
    pub my_commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoundTwo {
    pub(crate) my_ephemeral_secret: Scalar,
    pub my_ephemeral_public: EdwardsPoint,
    pub(crate) my_commitment: Commitment,
    pub their_commitments: Vec<Commitment>,
    pub their_ephemeral_publics: Vec<EdwardsPoint>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RoundThree {
    pub(crate) my_ephemeral_secret: Scalar,
    pub my_ephemeral_public: EdwardsPoint,
    pub my_commitment: Commitment,
    pub their_commitments: Vec<Commitment>,
    pub their_ephemeral_publics: Vec<EdwardsPoint>,
    pub my_partial_signature: Scalar,
    // pub their_partial_signatures // XXX needs new state
}

impl AggregateSigning {
    pub fn round_two(my_ephemeral_secret: Scalar,
                     my_ephemeral_public: EdwardsPoint,
                     my_commitment: Commitment) -> AggregateSigning {
        // XXX checking for scalars? check commitment isn't null?
        AggregateSigning::RoundOne {
            my_ephemeral_secret,
            my_ephemeral_public,
            my_commitment,
        }
    }

    pub fn round_two(&self,
                     their_commitments: Vec<Commitment>,
                     their_ephemeral_publics: Vec<EdwardsPoint>) -> AggregateSigning {
        match self {
            AggregateSigning::RoundOne => continue,
            _ => return AggregateSigning::Error,
        }

        if their_commitments.len() != their_ephemeral_publics.len() {
            return AggregateSigning::Error;
        }

        // XXX should we check the commitments here?

        AggregateSigning::RoundTwo {
            my_ephemeral_secret: self.my_ephemeral_secret,
            my_ephemeral_public: self.my_ephemeral_public,
            my_commitment: self.my_commitment,
            their_commitments,
            their_ephemeral_publics,
        }
    }

    pub fn round_three(&self) -> AggregateSigning {
        match self {
            AggregateSigning::RoundTwo => continue,
            _ => return AggregateSigning::Error,
        }

        AggregateSigning::RoundThree {
            my_ephemeral_secret: self.my_ephemeral_secret,
            my_ephemeral_public: self.my_ephemeral_public,
            my_commitment: self.my_commitment,
            their_commitments: self.their_commitments,
            their_ephemeral_publics: self.their_ephemeral_publics,
        }
    }
}
