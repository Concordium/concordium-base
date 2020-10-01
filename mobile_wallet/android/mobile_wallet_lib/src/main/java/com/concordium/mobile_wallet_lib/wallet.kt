package com.concordium.mobile_wallet_lib

external fun create_id_request_and_private_data(input: String) : ReturnValue
external fun create_credential(input: String) : ReturnValue
external fun create_transfer(input: String) : ReturnValue
external fun create_encrypted_transfer(input: String) : ReturnValue
external fun create_pub_to_sec_transfer(input: String) : ReturnValue
external fun create_sec_to_pub_transfer(input: String) : ReturnValue
external fun combine_encrypted_amounts(input1: String, input2: String) : ReturnValue
external fun decrypt_encrypted_amount(input: String) : ReturnValue
external fun check_account_address(input: String) : Boolean
external fun link_check(input: String) : String

fun loadWalletLib() {
    System.loadLibrary("mobile_wallet")
}

data class ReturnValue (val result : Int, val output : String)
