using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace IdissLib
{

    /// Here we provide classes that match some of the Rust types that involved with identity validation and creation. 
    /// Most of the field names of these classes are chosen so that they match JSON fields of JSON serialization of the corresponding Rust types.
    public class YearMonth {
        public string str{get;set;}

        public YearMonth (string s) {
            str = s;
        }
    }

    public class AttributeTag {
        public string tag{get;set;}

        public AttributeTag(string t)
        {
            tag = t;
        }
    }

    public class Attribute {
        public string attribute{get;set;}

        public Attribute(string a)
        {
            attribute = a;
        }
    }

    public class AttributeList
    {
        public YearMonth validTo{get;set;}
        public YearMonth createdAt{get;set;}
        public byte maxAccounts{get;set;}
        public Dictionary<AttributeTag, Attribute> chosenAttributes{get;set;}
    }

    public class PublicKey {
        public string schemeId{get;set;}
        public string verifyKey{get;set;}
    }

    public class PublicKeys {
        public Dictionary<string, PublicKey> keys{get;set;}
        public byte threshold{get;set;}
    }

    public class PubInfoForIp {
        public string idCredPub{get;set;}
        public string regId{get;set;}
        public PublicKeys publicKeys{get;set;}
    }

    public class IpArData {
        public string encPrfKeyShare{get;set;}
        public string proofComEncEq{get;set;}
    }

    public class ChoiceArData {
        public HashSet<UInt32> arIdentities{get;set;}
        public byte threshold{get;set;}
    }

    public class PreIdentityObject {
        public PubInfoForIp pubInfoForIp{get;set;}
        public Dictionary<string, IpArData> ipArData{get;set;}
        public ChoiceArData choiceArData{get;set;}
        public string idCredSecCommitment{get;set;}
        public string prfKeyCommitmentWithIP{get;set;}
        public List<string> prfKeySharingCoeffCommitments{get;set;}
        public string proofsOfKnowledge{get;set;}
    }

    public class IdentityObject {
        public PreIdentityObject preIdentityObject{get;set;}
        public AttributeList attributeList{get;set;}
        public string signature{get;set;}
    }

    public class VersionedPreIdentityObject {
        public UInt32 v {get;set;}
        public PreIdentityObject value {get;set;}
    }

    public class IdObjectRequest {
        public VersionedPreIdentityObject idObjectRequest{set;get;}
    }

    public class AnonymityRevocationRecord {
        public string idCredPub{get;set;}
        public Dictionary<string, IpArData> arData{get;set;}
        public byte maxAccounts{get;set;}
        public byte threshold{get;set;}
    }

    public class VersionedArRecord {
        public UInt32 v {get;set;}
        public AnonymityRevocationRecord value {get;set;}
    }

    public class AccountCredential {
        public string type{get;set;}
        public InitialCredentialDeploymentInfo contents{get;set;}
    }

    public class Policy {
        public YearMonth validTo{get;set;}
        public YearMonth createdAt{get;set;}
        public Dictionary<AttributeTag, Attribute> revealedAttributes{get;set;}
    }

    public class InitialCredentialDeploymentInfo {
        public PublicKeys credentialPublicKeys{get;set;}
        public string regId{get;set;}
        public UInt32 ipIdentity{get;set;}
        public Policy policy{get;set;}

        public string sig{get;set;}
    }

    public class AccountCredentialMessage {
        public UInt64 messageExpiry{get;set;}
        public AccountCredential credential{get;set;}
    }

    public class VersionedAccountCredentialMessage {
        public UInt32 v {get;set;}
        public AccountCredentialMessage value {get;set;}
    }

    public class VersionedIdentityObject {
        public UInt32 v {get;set;}
        public IdentityObject value {get;set;}
    }

    public class IdentityCreation {
        public VersionedIdentityObject idObj{get;set;}
        public VersionedArRecord arRecord{get;set;}
        public VersionedAccountCredentialMessage request{get;set;}
        public string accountAddress{get;set;}
    }

    public class Description {
        public string name{get;set;}
        public string url{get;set;}
        public string description{get;set;}
    }

    public class ArInfo {
        public UInt32 arIdentity{get;set;}
        public Description arDescription{get;set;}
        public string arPublicKey{get;set;}
    }

    public class VersionedArInfos {
        public UInt32 v {get;set;}
        public Dictionary<string, ArInfo> value {get;set;}
    }

    public class IpInfo {
        public UInt32 ipIdentity{get;set;}
        public Description ipDescription{get;set;}
        public string ipVerifyKey{get;set;}
        public string ipCdiVerifyKey{get;set;}
    }

    
    public class VersionedIpInfo {
        public UInt32 v {get;set;}
        public IpInfo value {get;set;}
    }

    public class GlobalContext {
        public string onChainCommitmentKey{get;set;}
        public string bulletproofGenerators{get;set;}
        public string genesisString{get;set;}
    }

    public class VersionedGlobalContext {
        public UInt32 v {get;set;}
        public GlobalContext value {get;set;}
    }

    public class IpPrivateKeys {
        public string ip_private_key{get;set;}
        public string ip_cdi_private_key{get;set;}
    }



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

    public class RequestValidationException: Exception {
        public RequestValidationException(string message): base(message) {
        }
    }

    public class IdentityCreationException: Exception {
        public IdentityCreationException(string message): base(message) {
        }
    }

    public static class Idiss {

        /// We first import the two C functions that are exported by the Rust library "idiss". 
        
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

        /// Instead of using the imported functions directly, two wrapper functions are provided that can be used on the relevant classes defined above. 
        /// The wrapper functions serialize the input to JSON bytes and then use the imported functions on pointers to these bytes. 

        /// The validate_request looks at bytes the resulting pointer is pointing to, and then either converts the bytes to a string (in case of success), 
        /// or throws an error described by the string the bytes converts to (otherwise)
        public static string validate_request(VersionedGlobalContext global, VersionedIpInfo ip_info, VersionedArInfos ars_infos, IdObjectRequest request){
            byte[] global_bytes = JsonSerializer.SerializeToUtf8Bytes(global);
            byte[] request_bytes = JsonSerializer.SerializeToUtf8Bytes(request);
            byte[] ars_infos_bytes = JsonSerializer.SerializeToUtf8Bytes(ars_infos);
            byte[] ip_info_bytes = JsonSerializer.SerializeToUtf8Bytes(ip_info);
            int out_length = 0;
            int out_success = 0;
            var result_ptr = validate_request_cs(global_bytes, global_bytes.Length, ip_info_bytes, ip_info_bytes.Length, ars_infos_bytes, ars_infos_bytes.Length, request_bytes, request_bytes.Length, out out_length,out out_success);
            byte[] out_bytes = new byte[out_length];
            Marshal.Copy(result_ptr, out_bytes, 0, out_length);
            if (out_success == 1){
                return Encoding.UTF8.GetString(out_bytes);
            } else if (out_success == -1) {
                var error_string = Encoding.UTF8.GetString(out_bytes);
                throw new RequestValidationException(error_string);
            } else {
                throw new RequestValidationException("Unknown error");
            }
        }

        
        /// The create_identity_object looks at bytes the resulting pointer is pointing to, and then either JSON deserializes the bytes to a IdentityCreation object (in case of success), 
        /// or throws an error described by the string the bytes converts to (otherwise).

        public static IdentityCreation create_identity_object(VersionedIpInfo ip_info, AttributeList alist, IdObjectRequest request, UInt64 expiry, IpPrivateKeys ip_keys){
            var options = new JsonSerializerOptions();
            options.Converters.Add(new DictionaryConverter());
            options.Converters.Add(new YearMonthConverter());
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
            if (out_success == 1) {
                return JsonSerializer.Deserialize<IdentityCreation>(id_out_bytes, options);
            } else if (out_success == -1) {
                var error_string = Encoding.UTF8.GetString(id_out_bytes);
                throw new IdentityCreationException(error_string);
            } else {
                throw new IdentityCreationException("Unkown error.");
            }
        }
    }
}
