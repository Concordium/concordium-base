package com.concordium.mobile_wallet_lib

external fun create_id_request_and_private_data(input: String) : ReturnValue
external fun create_credential(input: String) : ReturnValue
external fun create_id_request_and_private_data_v1(input: String) : ReturnValue
external fun generate_recovery_request(input: String) : ReturnValue
external fun prove_id_statement(input: String) : ReturnValue
external fun create_credential_v1(input: String) : ReturnValue
external fun generate_accounts(input: String) : ReturnValue
external fun create_transfer(input: String) : ReturnValue
external fun generate_baker_keys() : ReturnValue
external fun create_configure_delegation_transaction(input: String) : ReturnValue
external fun create_configure_baker_transaction(input: String) : ReturnValue
external fun create_encrypted_transfer(input: String) : ReturnValue
external fun create_pub_to_sec_transfer(input: String) : ReturnValue
external fun create_sec_to_pub_transfer(input: String) : ReturnValue
external fun combine_encrypted_amounts(input1: String, input2: String) : ReturnValue
external fun decrypt_encrypted_amount(input: String) : ReturnValue
external fun check_account_address(input: String) : Boolean
external fun link_check(input: String) : String
external fun get_identity_keys_and_randomness(input: String) : ReturnValue
external fun get_account_keys_and_randomness(input: String) : ReturnValue
external fun parameter_to_json(input: String) : ReturnValue
external fun sign_message(input: String) : ReturnValue
external fun create_account_transaction(input: String) : ReturnValue
external fun serialize_token_transfer_parameters(input: String) : ReturnValue


fun loadWalletLib() {
    System.loadLibrary("mobile_wallet")
}

data class ReturnValue (val result : Int, val output : String)
