'use strict';
const idiss = require('./pkg');

const fs = require('fs');

const request = fs.readFileSync('../rust-bins/wallet-notes/id-request.json', 'utf8')
const ars_infos = fs.readFileSync('./files/anonymity_revokers.json', 'utf8')
const ip_info = fs.readFileSync('./files/ip_info.json', 'utf8')

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

const private_key = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e4f791a70bdd528c23824cd1db8de55b89e807dcb757f0a929f3633dc87cfa55361813677fc79a67d8ec509ad0faa01d0a35bc0fb2542878b89397a51700b507b603a7e39cadcd970c561b0ed061fce1de479c47271721683064e5e4c5773c72f3a8cabac076ea893f6ae915bb24b6efee33d3beaa3d0788b9c0fb53ab574ce94467c9cda3a30740d254598611c3cc9804e39e64654f30a94ff45df41a94e58056c30ee46a95a66a95739269fc3b8db3eb01b2600385faa5791a16d22984c092a377417024eb4d03a164717241de73bc57fd83e8114a7cd3fd4491617ad985e435080973fa1a4e7fa750cc9c799847ab8add2e743f76874f425ecd1b08da9eee864c05b84899115a30b86d1fa196e4a5aae791ef7636c75017c5f52d0b127236b4502c82eede03d314e666d5ee8a14c24365ac0c56505b73a9a17048032ecc0285c3f12aec3ae00f150fea3bbdfb760307dbb16b5bf422a77faa847ee96b9b59631429bc4547e7d14c4870bd1b97c8e95f679b181b62bc97c435b1e8a74d7ac5b2f21c6e312ce51dda672886e0623849f88482cf71239db83c6775cd51819c67a6f2a7f8dfc47c3dce95204f3778f3f227474a5c70088b4e760364e8b4a6e5f27099472024b650301b0194b820c5bf1c7e14b250498ec8b1f2e194bc031ad887f5ebd327e482490847caf5301e379be4820c80f1340fe6eef2924605ffd654da666c4a260b5613d82216d15e90de7e62856d8e9627b14b6194c7f58969c68849202ae1770208080e5c2010bcbe23921be558e2d0d389afcc646f9fa8a7c19758871b6e7ba881d3f11913f75d5975df181907e075066857f2a6c9e29076ea8d4bd20161826a93ad55c25bd3d34f5921c800bd157133a3f33c19d0e7feb01b577bd7300c3f2394efad82ffb5061673020b130d0ee30ec780b7712062e59f938b0b34c42dae6f2ef0f631b6232736546b19e672498a80020422c276f4a2884690da950ede981f49e2ca79e9e3540a17b18ff0e82880151fc5476405a8978b17d1a6732e6726a644ad66198c59b05082e35beacc160955fde613fd3275acbf80606af4a9c22d38ca5f5e2116e5c674f6aa1fc9ffae17df2e20b533d1bd361b7a93ba326d6d1367dd579ff897eb644486d47686e98443c9de9f16bc9526ee9ad2d4743449ab4228ac9e159a35affebeeabf2db7f8898e4d6fc0efbb326eb9266f88e4a6cf9d03ffee9ae490ee868f417f24c659ef290f1e4f2ceba546afde3b97388423440701f55d461ba739b0d5015076cc0cdba03a63e7891e189418dfff04535bb1eca0baa43115c3f1ce7c933fdf9ba97b84e7957e87672a1d8b44ca7ce334caa17eab204b9f42df0c1e7e040bea15f36af424a3b77ce1cc494931aba7da56271"

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
