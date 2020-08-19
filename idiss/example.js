'use strict';
const idiss = require('./pkg');

const fs = require('fs');

const request = fs.readFileSync('../rust-bins/wallet-notes/id-request.json', 'utf8')
const ars_infos = fs.readFileSync('../rust-bins/wallet-notes/anonymity_revokers.json', 'utf8')
const ip_info = fs.readFileSync('../rust-bins/wallet-notes/ip_info.json', 'utf8')

console.log(idiss.validate_request(ip_info, ars_infos, request))

const alist = `{
      "chosenAttributes": {
        "countryOfResidence": "DE",
        "dob": "19800229",
        "firstName": "John",
        "idDocExpiresAt": "20291231",
        "idDocIssuedAt": "20200401",
        "idDocIssuer": "DK",
        "idDocNo": "1234567890",
        "idDocType": "1",
        "lastName": "Doe",
        "nationalIdNo": "DK123456789",
        "nationality": "DK",
        "sex": "1",
        "taxIdNo": "DE987654321"
      },
      "createdAt": "202004",
      "maxAccounts": 238,
      "validTo": "202104"
}`

const private_key = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e37887ff34a466c12cc31d7a3e8d6f1511fa9a9dbcf494a08e3ac4302a7fd274043d858fdf098a8ece7fe617417aedf0610cf4c3fca052bea9d0d6ac9c3e5c1686bcf2c97272311f99eccf75840f91e9102e794e2d575cd45d3659bf7c88f8b062a42be1f66a0e31e81e725366d4819567c4ca224a6121a8f5516a28916b546032ded09df99b73aa2e09c1cfde710c9f06530074a6097fc2bc5f5b941a5aecfbc32ef72de7ff6754391b12d94fd2523f32c96016317a2cf1ff416ab64a2c45e3f0f46d185bc6a620eb9a1e65dfd87d15d66f42a170a030f5439ec06374b03cd37627008de038d8ca15ba01cbc27ed7788046822e210351bbe2133f7596cd8f10024218829ae771549df8c88e2873b3b7ab05c19946303d4dcd363b873f103e3cf0af0825ce2b48bd6f49bf209536a70e1ff8560e48136ea407e8c45630be72fdb2f6ffe5177598bd9ec94362a8ca146b1e74b825ef6de26de3637aec14fd9c7d169e0020fb2990d2b7e6371f3e2798a3f42afb1c0f320d9c65863a0de8482a39158021f22b7525e2673d7ae8297e42fee81d323ceb08d64af84eed70ddd22d3e748de32838451fb91b38716221f49cde06b5b0efa7bd4fe6ed7c500e9cd3648d21c7d3b9fa45a58e1e48d066324be3fb0e75db852fe0e3b75b00474798afab80d31d8c868f3453271fb8504e725c79f0ba7bbfb3ca9e890e64f6318678e4327c7307f9120fc2b58da1b0998e8ebc1c3fc2c7d66334d0e3b73b8dbd7a9d6230d155637e712a82149e35b1e45b9031cead4152ac5784fdeca140ed9e82b1627d275454b93d6e892476fd01ba3cb177c812cb8ff76908cdf592e8c9a644e8466c8b671558fdbea593ec60bb11651bbbc28dc5f67c66f5e6e5b9479fa86460ea1e3411e57af2130738b7ad41669d463cd2fbbe0e0bac29ec697a02a70484e5d18f472703e8cba1a9cf44f4501e7c9488fd6db45b5de18dd6b433b535c753d696c24a0028ed99c2b99a786fa483f1d120ec3c9a3da6171e07a4c9378de980ab7d694083d5f2051087b3ef44505f4e86f88ab14b74bf05958c88b5c18a77f42a6e3dd8a3484f57b748c43b5867c508371c764de32c17b8ec0f31a8d6811e18b87ab86d03cf33d73c6a777524539da9c452804b983a5bacc4975e38b76e7fada413ac0fe1ecbc7fbc67266265eb8eb8ac264982c28cef0f58cf6469cac8c31e76e443e5f2a19598f44deb68b8108c6f5f4df845bc1d5404b37e2e96408c9cb63d1e4a37e3d3b2b080f7e895482b175bfecaed6259f93f219b590a5127cd540baaeb09d134378c7dca23fdfd76f65861002570ccb2ad34ac3225b9958301604f85ccd6857468efbe8650338f7c86fcc4355d65bae96552593d83da26e6fac943c3df16a11"

try {
    console.log(idiss.create_identity_object(ip_info, request, alist, private_key))
} catch(err) {
    console.error("Error creating id object: " + err)
}

try {
    console.log(idiss.create_anonymity_revocation_record(request))
} catch(err) {
    console.error("Error creating anonymity revocation record: " + err)
}

console.log("DONE");
