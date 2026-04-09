package idiss

// YearMonth is encoded as a JSON string in YYYYMM format.
type YearMonth string

// AttributeTag identifies an attribute in an identity attribute list.
type AttributeTag string

// Attribute is encoded as a JSON string value.
type Attribute string

// AccountAddress is encoded as a JSON string value.
type AccountAddress string

// Versioned wraps a versioned value.
type Versioned[T any] struct {
	V     uint32 `json:"v"`
	Value T      `json:"value"`
}

// Description is metadata describing an anonymity revoker or identity provider.
type Description struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// ARInfo is public information about an anonymity revoker.
type ARInfo struct {
	ARIdentity    uint32      `json:"arIdentity"`
	ARDescription Description `json:"arDescription"`
	ARPublicKey   string      `json:"arPublicKey"`
}

// IPInfo is public information about an identity provider.
type IPInfo struct {
	IPIdentity     uint32      `json:"ipIdentity"`
	IPDescription  Description `json:"ipDescription"`
	IPVerifyKey    string      `json:"ipVerifyKey"`
	IPCDIVerifyKey string      `json:"ipCdiVerifyKey"`
}

// GlobalContext contains cryptographic parameters shared by the chain.
type GlobalContext struct {
	OnChainCommitmentKey  string `json:"onChainCommitmentKey"`
	BulletproofGenerators string `json:"bulletproofGenerators"`
	GenesisString         string `json:"genesisString"`
}

// IPARData contains a user's encrypted anonymity-revocation data for one AR.
type IPARData struct {
	EncPrfKeyShare string `json:"encPrfKeyShare"`
	ProofComEncEq  string `json:"proofComEncEq"`
}

// ChoiceARData describes the chosen anonymity revocation parameters.
type ChoiceARData struct {
	ARIdentities []uint32 `json:"arIdentities"`
	Threshold    uint8    `json:"threshold"`
}

// PreIdentityObjectV1 is the request payload for the v1 issuance flow.
type PreIdentityObjectV1 struct {
	IDCredPub                     string              `json:"idCredPub"`
	IPARData                      map[string]IPARData `json:"ipArData"`
	ChoiceARData                  ChoiceARData        `json:"choiceArData"`
	IDCredSecCommitment           string              `json:"idCredSecCommitment"`
	PRFKeyCommitmentWithIP        string              `json:"prfKeyCommitmentWithIP"`
	PRFKeySharingCoeffCommitments []string            `json:"prfKeySharingCoeffCommitments"`
	ProofsOfKnowledge             string              `json:"proofsOfKnowledge"`
}

// IDObjectRequestV1 wraps a versioned pre-identity object.
type IDObjectRequestV1 struct {
	IDObjectRequest Versioned[PreIdentityObjectV1] `json:"idObjectRequest"`
}

// IDRecoveryRequest is a request to recover an identity.
type IDRecoveryRequest struct {
	IDCredPub string `json:"idCredPub"`
	Timestamp uint64 `json:"timestamp"`
	Proof     string `json:"proof"`
}

// IDRecoveryWrapper matches the JSON expected by the native recovery validator.
type IDRecoveryWrapper struct {
	IDRecoveryRequest Versioned[IDRecoveryRequest] `json:"idRecoveryRequest"`
}

// AttributeList contains the mandatory and chosen user attributes.
type AttributeList struct {
	ValidTo          YearMonth                  `json:"validTo"`
	CreatedAt        YearMonth                  `json:"createdAt"`
	MaxAccounts      uint8                      `json:"maxAccounts"`
	ChosenAttributes map[AttributeTag]Attribute `json:"chosenAttributes"`
}

// IdentityObjectV1 is returned to the user in the v1 issuance flow.
type IdentityObjectV1 struct {
	PreIdentityObject PreIdentityObjectV1 `json:"preIdentityObject"`
	AttributeList     AttributeList       `json:"attributeList"`
	Signature         string              `json:"signature"`
}

// AnonymityRevocationRecord is stored by the identity provider for revocation support.
type AnonymityRevocationRecord struct {
	IDCredPub           string              `json:"idCredPub"`
	ARData              map[string]IPARData `json:"arData"`
	MaxAccounts         uint8               `json:"maxAccounts"`
	RevocationThreshold uint8               `json:"revocationThreshold"`
}

// IdentityCreationV1 is the v1 issuance response.
type IdentityCreationV1 struct {
	IDObj    Versioned[IdentityObjectV1]          `json:"idObj"`
	ARRecord Versioned[AnonymityRevocationRecord] `json:"arRecord"`
}
