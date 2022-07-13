
using System;
using System.Collections.Generic;

namespace IdissLib
{
    /// Here we provide classes that match some of the Rust types that are involved with identity validation and creation. 
    /// Most of the field names of these classes are chosen so that they match JSON fields of the JSON serialization of the corresponding Rust types.

    /// YearMonth in Gregorian calendar.
    /// The year is in Gregorian calendar and months are numbered from 1, i.e.,
    /// 1 is January, ..., 12 is December.
    /// Year must be a 4 digit year, i.e., between 1000 and 9999.
    public class YearMonth
    {
        public string str { get; set; }

        public YearMonth(string s)
        {
            str = s;
        }
    }

    /// Attribute tags are represented as a string. 
    /// The string needs to be one of the following:
    /// "firstName","lastName","sex","dob","countryOfResidence","nationality",
    /// "idDocType", "idDocNo", "idDocIssuer", "idDocIssuedAt", "idDocExpiresAt",
    /// "nationalIdNo","taxIdNo".
    public class AttributeTag
    {
        public string tag { get; set; }

        public AttributeTag(string t)
        {
            tag = t;
        }
    }

    /// Attribute values.
    /// All currently supported attributes are string values.
    public class Attribute
    {
        public string attribute { get; set; }

        public Attribute(string a)
        {
            attribute = a;
        }
    }

    /// An attribute list consists of some mandatory attributes and some user selected attributes.
    public class AttributeList
    {
        public YearMonth validTo { get; set; }
        public YearMonth createdAt { get; set; }
        public byte maxAccounts { get; set; }
        public Dictionary<AttributeTag, Attribute> chosenAttributes { get; set; }
    }

    /// Public verification key for a given signature scheme.
    /// Only ed25519 is currently supported.
    public class PublicKey
    {
        public string schemeId { get; set; }
        public string verifyKey { get; set; }
    }

    /// Public credential keys of an account holder, together with the threshold
    /// needed for a valid signature on a transaction.
    public class PublicKeys
    {
        public Dictionary<string, PublicKey> keys { get; set; }
        public byte threshold { get; set; }
    }


    /// This class contains information from the account holder that the identity
    /// provider needs in order to create the initial credential for the account
    /// holder. It contains idCredPub, regId and the public credential keys.
    /// It is part of the preidentity object.
    public class PubInfoForIp
    {
        public string idCredPub { get; set; }
        public string regId { get; set; }
        public PublicKeys publicKeys { get; set; }
    }

    /// The data relating to a single anonymity revoker
    /// sent by the account holder to the identity provider.
    public class IpArData
    {
        public string encPrfKeyShare { get; set; }
        public string proofComEncEq { get; set; }
    }

    // NOTE: This class is redundant, but it is needed
    // for compatibility.
    /// Choice of anonymity revocation parameters.
    public class ChoiceArData
    {
        public HashSet<UInt32> arIdentities { get; set; }
        public byte threshold { get; set; }
    }

    /// Information sent from the account holder to the identity provider.
    /// This includes only cryptographic parts.
    public class PreIdentityObject
    {
        public PubInfoForIp pubInfoForIp { get; set; }
        public Dictionary<string, IpArData> ipArData { get; set; }
        public ChoiceArData choiceArData { get; set; }
        public string idCredSecCommitment { get; set; }
        public string prfKeyCommitmentWithIP { get; set; }
        public List<string> prfKeySharingCoeffCommitments { get; set; }
        public string proofsOfKnowledge { get; set; }
    }

    /// Information sent from the account holder to the identity provider in the version 1 flow,
    /// where no initial account is created.
    /// This includes only cryptographic parts.
    public class PreIdentityObjectV1
    {
        public string idCredPub { get; set; }
        public Dictionary<string, IpArData> ipArData { get; set; }
        public ChoiceArData choiceArData { get; set; }
        public string idCredSecCommitment { get; set; }
        public string prfKeyCommitmentWithIP { get; set; }
        public List<string> prfKeySharingCoeffCommitments { get; set; }
        public string proofsOfKnowledge { get; set; }
    }

    /// A request for recovering an identity. Contatins proof of knowledge of idCredSec for the given idCredPub.
    public class IdRecoveryRequest
    {
        public string idCredPub { get; set; }
        public UInt64 timestamp { get; set; }
        public string proof { get; set; }
    }

    /// A wrapper to match the JSON serialization of the request expected by the imported C function "validate_recovery_request_cs".
    public class IdRecoveryWrapper
    {
        public Versioned<IdRecoveryRequest> idRecoveryRequest { set; get; }
    }

    /// The data the identity provider sends back to the user.
    public class IdentityObject
    {
        public PreIdentityObject preIdentityObject { get; set; }
        public AttributeList attributeList { get; set; }
        public string signature { get; set; }
    }

    /// The data the identity provider sends back to the user.
    public class IdentityObjectV1
    {
        public PreIdentityObjectV1 preIdentityObject { get; set; }
        public AttributeList attributeList { get; set; }
        public string signature { get; set; }
    }

    /// An IdObjectRequest is a versioned PreIdentityObject.
    public class IdObjectRequest
    {
        public Versioned<PreIdentityObject> idObjectRequest { set; get; }
    }

    /// An IdObjectRequestV1 is a versioned PreIdentityObjectV1.
    public class IdObjectRequestV1
    {
        public Versioned<PreIdentityObjectV1> idObjectRequest { set; get; }
    }

    /// Data that needs to be stored by the identity provider to support anonymity
    /// revocation.
    public class AnonymityRevocationRecord
    {
        public string idCredPub { get; set; }
        public Dictionary<string, IpArData> arData { get; set; }
        public byte maxAccounts { get; set; }
        public byte revocationThreshold { get; set; }
    }

    /// A wrapper around the InitialCredentialDeploymentInfo class.
    /// The identity provider only creates initial accounts on behalf of the user,
    /// which is why the type of "contents" is a InitialCredentialDeploymentInfo.
    // The wrapper has the fields "type" and "contents" so that
    // it can deserialize the JSON output it gets from the imported
    // function "create_identity_object_cs".
    public class AccountCredential
    {
        public string type { get; set; }
        public InitialCredentialDeploymentInfo contents { get; set; }
    }

    /// A policy is (currently) revealed values of attributes that are part of the
    /// identity object. Policies are part of credentials.
    public class Policy
    {
        public YearMonth validTo { get; set; }
        public YearMonth createdAt { get; set; }
        public Dictionary<AttributeTag, Attribute> revealedAttributes { get; set; }
    }


    /// Information needed to create an `initial` account. This account is created
    /// on behalf of the user by the identity provider.
    public class InitialCredentialDeploymentInfo
    {
        /// Public keys of the account holder this credential belongs to.
        public PublicKeys credentialPublicKeys { get; set; }
        /// Credential registration id of the credential.
        public string regId { get; set; }
        /// Identity of the identity provider who signed the identity object from
        /// which this credential is derived.
        public UInt32 ipIdentity { get; set; }
        /// Policy of this credential object.
        public Policy policy { get; set; }
        /// Signature by the identity provider on the initial account creation.

        public string sig { get; set; }
    }

    /// Account credential message is an account credential together with a message
    /// expiry. This is the payload that is sent to the chain when new accounts are
    /// created. Since the identity provider never creates normal accounts (but only)
    /// initial accounts, the AccountCredential (defined above) only contains
    /// initial credential deployment info. 
    public class AccountCredentialMessage
    {
        public UInt64 messageExpiry { get; set; }
        public AccountCredential credential { get; set; }
    }

    /// IdentityCreation is defined to match the JSON that is sent back (if nothing went wrong) from
    /// the imported function "create_identity_object_cs". 
    /// The identity provider is then meant to send the versioned identity object to back to the user,
    /// to store the attribute list from the identity object together with the versioned anynomity revocation
    /// and the account address. The versioned account credential message should be sent to the chain. 
    public class IdentityCreation
    {
        public Versioned<IdentityObject> idObj { get; set; }
        public Versioned<AnonymityRevocationRecord> arRecord { get; set; }
        public Versioned<AccountCredentialMessage> request { get; set; }
        public AccountAddress accountAddress { get; set; }
    }


    /// IdentityCreationV1 is defined to match the JSON that is sent back (if nothing went wrong) from
    /// the imported function "create_identity_object_v1_cs".
    /// The identity provider is then meant to send the versioned identity object to back to the user,
    /// to store the attribute list from the identity object together with the versioned anynomity revocation.
    public class IdentityCreationV1
    {
        public Versioned<IdentityObjectV1> idObj { get; set; }
        public Versioned<AnonymityRevocationRecord> arRecord { get; set; }
    }

    /// An account address represented as a string.
    public class AccountAddress
    {
        public string address { get; set; }

        public AccountAddress(string s)
        {
            address = s;
        }

        public override bool Equals(Object obj)
        {
            AccountAddress accountAddress = obj as AccountAddress;
            if (address == null)
                return false;
            else
                return address.Equals(accountAddress.address);
        }

        public override int GetHashCode()
        {
            return this.address.GetHashCode();
        }

        public override string ToString()
        {
            return address.ToString();
        }
    }



    /// Description either of an anonymity revoker or identity provider.
    /// Metadata that should be visible on the chain.
    public class Description
    {
        public string name { get; set; }
        public string url { get; set; }
        public string description { get; set; }
    }

    /// Information on a single anonymity revoker held by the IP.
    /// Typically an IP will hold a more than one.
    public class ArInfo
    {
        /// Unique identifier of the anonymity revoker. 
        public UInt32 arIdentity { get; set; }
        /// Free form description, e.g., how to contact them off-chain
        public Description arDescription { get; set; }
        /// Elgamal encryption key of the anonymity revoker
        public string arPublicKey { get; set; }
    }

    /// Public information about an identity provider.
    public class IpInfo
    {
        /// Unique identifier of the identity provider.
        public UInt32 ipIdentity { get; set; }
        /// Free form description, e.g., how to contact them off-chain
        public Description ipDescription { get; set; }
        /// PS public key of the IP
        public string ipVerifyKey { get; set; }
        /// Ed public key of the IP
        public string ipCdiVerifyKey { get; set; }
    }


    /// A set of cryptographic parameters that are particular to the chain and
    /// shared by everybody that interacts with the chain.  
    public class GlobalContext
    {
        /// A shared commitment key known to the chain and the account holder (and
        /// therefore it is public). The account holder uses this commitment key to
        /// generate commitments to values in the attribute list.
        public string onChainCommitmentKey { get; set; }
        /// Generators for the bulletproofs used for range proofs.
        public string bulletproofGenerators { get; set; }
        /// A free-form string used to distinguish between different chains even if
        /// they share other parameters.
        public string genesisString { get; set; }
    }

    /// The private identity provider keys
    public class IpPrivateKeys
    {
        /// The private key used to sign the identity object sent back to the user.
        public string ipPrivateKey { get; set; }
        /// The private key used to sign the initial account creation message.
        public string ipCdiPrivateKey { get; set; }
    }

    public class Versioned<T>
    {
        public UInt32 v { get; set; }
        public T value { get; set; }
    }
}