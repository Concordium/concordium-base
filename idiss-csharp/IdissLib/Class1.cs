using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Text.Json.Serialization;

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

    /// The data the identity provider sends back to the user.
    public class IdentityObject
    {
        public PreIdentityObject preIdentityObject { get; set; }
        public AttributeList attributeList { get; set; }
        public string signature { get; set; }
    }

    /// A versioned pre-identity object. 
    public class VersionedPreIdentityObject
    {
        public UInt32 v { get; set; }
        public PreIdentityObject value { get; set; }
    }

    /// A IdObjectRequest is a versioned pre-identity object.
    public class IdObjectRequest
    {
        public VersionedPreIdentityObject idObjectRequest { set; get; }
    }

    /// Data that needs to be stored by the identity provider to support anonymity
    /// revocation.
    public class AnonymityRevocationRecord
    {
        public string idCredPub { get; set; }
        public Dictionary<string, IpArData> arData { get; set; }
        public byte maxAccounts { get; set; }
        public byte threshold { get; set; }
    }

    /// A versioned anonymity revocation record.
    public class VersionedArRecord
    {
        public UInt32 v { get; set; }
        public AnonymityRevocationRecord value { get; set; }
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

    /// A versioned account credential message.
    public class VersionedAccountCredentialMessage
    {
        public UInt32 v { get; set; }
        public AccountCredentialMessage value { get; set; }
    }

    /// A versioned identity object.
    public class VersionedIdentityObject
    {
        public UInt32 v { get; set; }
        public IdentityObject value { get; set; }
    }

    /// IdentityCreation is defined to match the JSON that is sent back (if nothing went wrong) from
    /// the imported function "create_identity_object_cs". 
    /// The identity provider is then meant to send the versioned identity object to back to the user,
    /// to store the attribute list from the identity object together with the versioned anynomity revocation
    /// and the account address. The versioned account credential message should be sent to the chain. 
    public class IdentityCreation
    {
        public VersionedIdentityObject idObj { get; set; }
        public VersionedArRecord arRecord { get; set; }
        public VersionedAccountCredentialMessage request { get; set; }
        public AccountAddress accountAddress { get; set; }
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

    /// A versioned map of ArInfos.
    public class VersionedArInfos
    {
        public UInt32 v { get; set; }
        public Dictionary<string, ArInfo> value { get; set; }
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

    /// Versioned identity provider info
    public class VersionedIpInfo
    {
        public UInt32 v { get; set; }
        public IpInfo value { get; set; }
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

    /// A versioned global context.
    public class VersionedGlobalContext
    {
        public UInt32 v { get; set; }
        public GlobalContext value { get; set; }
    }

    /// The private identity provider keys
    public class IpPrivateKeys
    {
        /// The private key used to sign the identity object sent back to the user.
        public string ip_private_key { get; set; }
        /// The private key used to sign the initial account creation message.
        public string ip_cdi_private_key { get; set; }
    }


    /// A JsonConverter for JSON serialization and deserialization of objects of type Dictionary<AttributeTag, Attribute>
    // It is public so that in case be used in tests and from applications using the library.
    public class DictionaryConverter : JsonConverter<Dictionary<AttributeTag, Attribute>>
    {
        public override Dictionary<AttributeTag, Attribute> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException();
            }
            var value = new Dictionary<AttributeTag, Attribute>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return value;
                }
                string keyString = reader.GetString();
                var key = new AttributeTag(keyString);
                reader.Read();
                string itemString = reader.GetString();
                var itemValue = new Attribute(itemString);
                value.Add(key, itemValue);
            }
            throw new JsonException("Error Occured");
        }

        public override void Write(Utf8JsonWriter writer, Dictionary<AttributeTag, Attribute> value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            foreach (KeyValuePair<AttributeTag, Attribute> item in value)
            {
                writer.WriteString(item.Key.tag, item.Value.attribute);
            }
            writer.WriteEndObject();
        }
    }

    /// A JsonConverter for JSON serialization and deserialization of objects of type YearMonth.
    public class YearMonthConverter : JsonConverter<YearMonth>
    {
        public override YearMonth Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string str = reader.GetString();
            return new YearMonth(str);
        }

        public override void Write(Utf8JsonWriter writer, YearMonth value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.str);
        }
    }


    /// A JsonConverter for JSON serialization and deserialization of objects of type AccountAddress.
    public class AccountAddressConverter : JsonConverter<AccountAddress>
    {
        public override AccountAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string address = reader.GetString();
            return new AccountAddress(address);
        }

        public override void Write(Utf8JsonWriter writer, AccountAddress value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.address);
        }
    }

    /// An Exception to be thrown in case of validation failure of a request.
    public class RequestValidationException : Exception
    {
        public RequestValidationException(string message) : base(message)
        {
        }
    }

    /// An Exception to be thrown in case that identity creation does not succeed.
    public class IdentityCreationException : Exception
    {
        public IdentityCreationException(string message) : base(message)
        {
        }
    }

    public static class Idiss
    {
        /// Import of the two C functions that are exported by the Rust library "idiss". 
        [DllImport("idiss.dll")]
        private static extern IntPtr validate_request_cs([MarshalAs(UnmanagedType.LPArray)] byte[] ctx, int ctx_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] ars_infos, int ars_infos_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len, out int out_length, out int out_success);

        [DllImport("idiss.dll")]
        private static extern IntPtr create_identity_object_cs([MarshalAs(UnmanagedType.LPArray)] byte[] ip_info, int ip_info_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] request, int request_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] alist, int alist_len,
        UInt64 expiry,
        [MarshalAs(UnmanagedType.LPArray)] byte[] ip_private_key, int ip_private_key_ptr_len,
        [MarshalAs(UnmanagedType.LPArray)] byte[] ip_cdi_private_key, int ip_cdi_private_key_ptr_len,
        out int out_length, out int out_success);

        /// A wrapper around the imported C function "validate_request_cs". The arguments are
        /// - global - the versioned global context
        /// - ip_info - the versioned identity provider info
        /// - ars_info - the versioned map of ArInfos
        /// - request - the identity object request
        /// The function either
        /// - returns the address of the initial account, if the request is valid, or
        /// - throws an exception, if the request is invalid or the input is malformed. 
        public static AccountAddress validate_request(VersionedGlobalContext global, VersionedIpInfo ip_info, VersionedArInfos ars_infos, IdObjectRequest request)
        {
            byte[] global_bytes = JsonSerializer.SerializeToUtf8Bytes(global);
            byte[] request_bytes = JsonSerializer.SerializeToUtf8Bytes(request);
            byte[] ars_infos_bytes = JsonSerializer.SerializeToUtf8Bytes(ars_infos);
            byte[] ip_info_bytes = JsonSerializer.SerializeToUtf8Bytes(ip_info);
            int out_length = 0;
            int out_success = 0;
            var result_ptr = validate_request_cs(global_bytes, global_bytes.Length, ip_info_bytes, ip_info_bytes.Length, ars_infos_bytes, ars_infos_bytes.Length, request_bytes, request_bytes.Length, out out_length, out out_success);
            byte[] out_bytes = new byte[out_length];
            Marshal.Copy(result_ptr, out_bytes, 0, out_length);
            if (out_success == 1)
            {
                return new AccountAddress(Encoding.UTF8.GetString(out_bytes));
            }
            else if (out_success == -1)
            {
                var error_string = Encoding.UTF8.GetString(out_bytes);
                throw new RequestValidationException(error_string);
            }
            else
            {
                throw new RequestValidationException("Unknown error");
            }
        }

        /// A wrapper around the imported C function "create_identity_object_cs". The arguments are
        /// - ip_info - the versioned identity provider info
        /// - alist - the attribute list containing the attributes of the user
        /// - request - the identity object request. This is the request that the wallet sends which contains cryptographic values and proofs.
        /// - expiry - the expiry time of the account creation message sent to the chain. This is just a unix timestamp that should be set to, e.g., now + 5 min.
        /// - ip_keys - the private keys of the identity provider
        /// The function either
        /// - returns a `IdentityCreation` object containing 
        ///     * the identity object that is returned to the user
        ///     * the anonymity revocation record
        ///     * the initial account creation object that is sent to the chain
        ///     * the address of the inital account, or 
        ///  - throws an exception, if any of the inputs are malformed. 

        public static IdentityCreation create_identity_object(VersionedIpInfo ip_info, AttributeList alist, IdObjectRequest request, UInt64 expiry, IpPrivateKeys ip_keys)
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new DictionaryConverter());
            options.Converters.Add(new YearMonthConverter());
            options.Converters.Add(new AccountAddressConverter());
            byte[] request_bytes = JsonSerializer.SerializeToUtf8Bytes(request);
            byte[] ip_info_bytes = JsonSerializer.SerializeToUtf8Bytes(ip_info);
            byte[] alist_bytes = JsonSerializer.SerializeToUtf8Bytes(alist, options);
            byte[] ip_private_key_bytes = Encoding.UTF8.GetBytes(ip_keys.ip_private_key);
            byte[] ip_cdi_private_key_bytes = Encoding.UTF8.GetBytes(ip_keys.ip_cdi_private_key);
            int id_out_length = 0;
            int out_success = 0;
            var id_ptr = create_identity_object_cs(ip_info_bytes, ip_info_bytes.Length, request_bytes, request_bytes.Length, alist_bytes, alist_bytes.Length,
             expiry, ip_private_key_bytes, ip_private_key_bytes.Length, ip_cdi_private_key_bytes, ip_cdi_private_key_bytes.Length, out id_out_length, out out_success);
            byte[] id_out_bytes = new byte[id_out_length];
            Marshal.Copy(id_ptr, id_out_bytes, 0, id_out_length);
            if (out_success == 1)
            {
                return JsonSerializer.Deserialize<IdentityCreation>(id_out_bytes, options);
            }
            else if (out_success == -1)
            {
                var error_string = Encoding.UTF8.GetString(id_out_bytes);
                throw new IdentityCreationException(error_string);
            }
            else
            {
                throw new IdentityCreationException("Unkown error.");
            }
        }
    }
}
