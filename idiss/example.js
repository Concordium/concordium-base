'use strict';
const idiss = require('./pkg');

const fs = require('fs');

const request = fs.readFileSync('../rust-bins/wallet-notes/id-request.json', 'utf8')
const ip_info = fs.readFileSync('../rust-bins/wallet-notes/input.json', 'utf8')

console.log(idiss.validate_request(ip_info, request))

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

const private_key = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e1844efc1089bc59baf8c5d8671ece1c73c97488ccd081e614413bde474147a762456ee6266f749168c57219b8d028967f3d38593d2b29524b9f6e72f9c4f1c28205ea4def8b1d84e878ac80ab132b33570d1d58f9c4fe626ca47baacceca47f867d8150c43eadb6b6ccde68fd7e7a6d4979a507ffc8ca95cafc3384137a1896067b732179bf35ae5ffb9a464cd3ee672581a1c77d0212c2109c698a5f4ff1f2d0aa711d075c6f2b4ca0f2dbf351a584f704954b62398ab8376d7ea84f7bf69366b4df740d5a23ff43671f4df9bdb542f4cc6f53aa15af9aaad528c6ad26af4555f170fbaa2d82d55ab85594f70d9b7383a2b5a09a300ea30c27e7f61d7ece05d1d56a0a09d1aa7bfe28ea4a725de59b2acf206aa08f2cb56b616914068a2117a2b35c98da9b8764dac76b8c33270690a14b57581ca68aff73aec3438e0cf34251e8466e899d425cd6ee0ae07ac325d712203304a25d5971e1dca5e6831a00e4d1e1b760abf1f901b01ae05fe2efdf37efe9736184acd931dbe183b352e68e36841f061efba72f6d07983c0069d93473ac7ab5cc23bd647f2b41e033d38ee5c730b558668bcd2ab026381f45195af21d575a627e285412da4ff4241260312bcd9472dc0a4289e73b594b35b8c7ab8feb637c4576c5b521b68feb513d82324b0360c57e1e1ffd8d37d6bafbfc5c2b45af4292636666543439f67caf6cc0f23d755548036ebfe4e5a3b1fe210d643f1012f56aecd6288b30924b86a53a9990511640a90a09724ebbdbfa0ebf552b102ac2e188197e4fc5cef4c113c14a56a3acf2a4f5331e6059649dd2d095d9a320111154a092e832b0c97eb7276a3dae7d32e3a0c19149dbc0c5284963eac2da0eadc918a63a96a4dc93117f546682ca68217304729bc87f1645788bd10328cc8ed9e36657993554d9433132a39e0c0f2572a3e3b2d44485ab46fb1983f03eff67faef2c27823da6afcc0c09598a03fbc2e67e13a5550ca92ba578d7f202316bc5ac4572b3de4da40354e89006b22271752c79f6c698bdeffad7e8bad95369113a18a94bcb7bff798a7ff38d4da89e8707567286ff799c08c40ea4ddd3634a4419ecc341eee7dea97a78354c42af8a057bffb391932aea5bf9c0209111fe524120e4b5d1c2ecdfaf74f7a8fce2d312f74a0e97d6cf96fbff65ed2d306f3eb8fd086b416aee1f8e34a7cd9eb1840e8251e7b8a7e0d7b00f4f13f9fe9aab431d1eeafd9ea900361e21339be1c8720f75e2fe42ddb34f901f050b5c00a29d8a7c96d36e98b4ad1ff3a215b1933d6fdb92f37d53c95729631ebedf9d50b97684b0b77aaf4ffd012164c02ec7e3e66840b22362f66246fe19a79b42eb8b3e8cc5e49d08277db2415a5ac01d54b5bd9fdcbe69ad58a36"

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
