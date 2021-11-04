using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;

namespace IdissLib
{
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
        /// - ipInfo - the versioned identity provider info
        /// - arsInfo - the versioned map of ArInfos
        /// - request - the identity object request
        /// The function either
        /// - returns the address of the initial account, if the request is valid, or
        /// - throws an exception, if the request is invalid or the input is malformed. 
        public static AccountAddress ValidateRequest(Versioned<GlobalContext> global, Versioned<IpInfo> ipInfo, Versioned<Dictionary<string, ArInfo>> arsInfos, IdObjectRequest request)
        {
            byte[] globalBytes = JsonSerializer.SerializeToUtf8Bytes(global);
            byte[] requestBytes = JsonSerializer.SerializeToUtf8Bytes(request);
            byte[] arsInfosBytes = JsonSerializer.SerializeToUtf8Bytes(arsInfos);
            byte[] ipInfoBytes = JsonSerializer.SerializeToUtf8Bytes(ipInfo);
            int outLength = 0;
            int outSuccess = 0;
            var resultPtr = validate_request_cs(globalBytes, globalBytes.Length, ipInfoBytes, ipInfoBytes.Length, arsInfosBytes, arsInfosBytes.Length, requestBytes, requestBytes.Length, out outLength, out outSuccess);
            byte[] outBytes = new byte[outLength];
            Marshal.Copy(resultPtr, outBytes, 0, outLength);
            if (outSuccess == 1)
            {
                return new AccountAddress(Encoding.UTF8.GetString(outBytes));
            }
            else if (outSuccess == -1)
            {
                var errorString = Encoding.UTF8.GetString(outBytes);
                throw new RequestValidationException(errorString);
            }
            else
            {
                throw new RequestValidationException("Unknown error");
            }
        }

        /// A wrapper around the imported C function "create_identity_object_cs". The arguments are
        /// - ipInfo - the versioned identity provider info
        /// - alist - the attribute list containing the attributes of the user
        /// - request - the identity object request. This is the request that the wallet sends which contains cryptographic values and proofs.
        /// - expiry - the expiry time of the account creation message sent to the chain. This is just a unix timestamp that should be set to, e.g., now + 5 min.
        /// - ipKeys - the private keys of the identity provider
        /// The function either
        /// - returns a `IdentityCreation` object containing 
        ///     * the identity object that is returned to the user
        ///     * the anonymity revocation record
        ///     * the initial account creation object that is sent to the chain
        ///     * the address of the inital account, or 
        ///  - throws an exception, if any of the inputs are malformed. 

        public static IdentityCreation CreateIdentityObject(Versioned<IpInfo> ipInfo, AttributeList alist, IdObjectRequest request, UInt64 expiry, IpPrivateKeys ipKeys)
        {
            var options = new JsonSerializerOptions();
            options.Converters.Add(new DictionaryConverter());
            options.Converters.Add(new YearMonthConverter());
            options.Converters.Add(new AccountAddressConverter());
            byte[] requestBytes = JsonSerializer.SerializeToUtf8Bytes(request);
            byte[] ipInfoBytes = JsonSerializer.SerializeToUtf8Bytes(ipInfo);
            byte[] alistBytes = JsonSerializer.SerializeToUtf8Bytes(alist, options);
            byte[] ipPrivateKeyBytes = Encoding.UTF8.GetBytes(ipKeys.ipPrivateKey);
            byte[] ipCdiPrivateKeyBytes = Encoding.UTF8.GetBytes(ipKeys.ipCdiPrivateKey);
            int idOutLength = 0;
            int outSuccess = 0;
            var idPtr = create_identity_object_cs(ipInfoBytes, ipInfoBytes.Length, requestBytes, requestBytes.Length, alistBytes, alistBytes.Length,
             expiry, ipPrivateKeyBytes, ipPrivateKeyBytes.Length, ipCdiPrivateKeyBytes, ipCdiPrivateKeyBytes.Length, out idOutLength, out outSuccess);
            byte[] idOutBytes = new byte[idOutLength];
            Marshal.Copy(idPtr, idOutBytes, 0, idOutLength);
            if (outSuccess == 1)
            {
                return JsonSerializer.Deserialize<IdentityCreation>(idOutBytes, options);
            }
            else if (outSuccess == -1)
            {
                var errorString = Encoding.UTF8.GetString(idOutBytes);
                throw new IdentityCreationException(errorString);
            }
            else
            {
                throw new IdentityCreationException("Unkown error.");
            }
        }
    }
}
