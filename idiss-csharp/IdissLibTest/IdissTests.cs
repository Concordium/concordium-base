using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text.Json;
using IdissLib;
using System.Collections.Generic;

namespace IdissLibTest
{
    [TestClass]
    public class IdissTests
    {
        [TestMethod]
        public void TestValidationAndIdCreation()
        {
            StreamReader r = new StreamReader("../../../../data/global.json");
            string globalStr = r.ReadToEnd();
            var global = JsonSerializer.Deserialize<Versioned<GlobalContext>>(globalStr);
            StreamReader r2 = new StreamReader("../../../../data/valid_request.json");
            string requestStr = r2.ReadToEnd();
            var request = JsonSerializer.Deserialize<IdObjectRequest>(requestStr);
            StreamReader r3 = new StreamReader("../../../../data/anonymity_revokers.json");
            string arsInfosStr = r3.ReadToEnd();
            var arsInfos = JsonSerializer.Deserialize<Versioned<Dictionary<string, ArInfo>>>(arsInfosStr);
            StreamReader r4 = new StreamReader("../../../../data/identity_provider.pub.json");
            string ipInfoStr = r4.ReadToEnd();
            var ipInfo = JsonSerializer.Deserialize<Versioned<IpInfo>>(ipInfoStr);
            var options = new JsonSerializerOptions();
            options.Converters.Add(new DictionaryConverter());
            options.Converters.Add(new YearMonthConverter());

            StreamReader r5 = new StreamReader("../../../../data/alist.json");
            string alistStr = r5.ReadToEnd();
            var alist = JsonSerializer.Deserialize<AttributeList>(alistStr, options);

            var ipKeys = new IpPrivateKeys
            {
                ipPrivateKey = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e2c7551ad2184d5503fae6f827b2c4ead26ced6d2cc77d9afb7cfa3a6b4079ded59548320ec6cb2e8e2832f05978a3e78194562dd8db40c16104def1460c8746a4b51a6eef6d2d399cb61deaf44a2e051fc789607e62ca18de0b43c0993eb9c8b0f948cfd129acdc5069d388ecd225fd265c3c5843174ef683a4ce7cb132721c452126c3507884c646365177e18a91df68637dcd582263c5de3a23b41acc2d3925649d4741327271841d9ea328ad389d1697d47ad2f62600b35fa0d5b8dd3c2b86f1a786b2a0074933b45c61109fe8d47ccd8fc7334dc925facf2eb9ccf850d7a63fa089edb6acf70b9f463d96b6f5ad3c4a74efe7df749d6b8ea9d95ee9dfc5a587d7d07c484b26dac3c2add6201d08084af9293d9ac3feec5607e8df365816d14a48f512e8d17091db0e451332706523005ae2ee9bc444df94e805d300666f8293484e951df8b8ed167bf9cafa865c41532d900281b81d7484521f2482159b66bbd958441358bf16733f0dd63c8869a2c8f6778d294f2e437c2b257f18deb5c0114ba156af66ccb315ca1c8b817ccbf1c440667c03790b555cb1489328fdd6d38e52d3df8b9b3fe003a1f76c2c56ea7f5acdf2bd0ef2dfbbe1fd03234935e235004c8666b7dc5eebf305965fc880400d1a6ddcb993631ec14ab316849d8fbf426bbae261d82810fd6f19cd0f1626f57af3d66c3ac9e68215effd94a8a85dd1c70ee71b4c591d0d06cf19ff0658f303201788a10629ecd04b4b9437eec09d20d5245efa68fe00d7ea756ad5c928c2b5a2504672a0bc87498deb77345ad1105fa399976ab42441b90454d44c0a4e9173accd1b7ef81d20af25518e885310e47cb4ea7af6cd3a4c4e72affd0efcb830c8a200a6bf03c6bfa13d648ee937ffa24545b1e3081b23994c435513ec6f705fa8b6d9f974b1d0cb23700c362362ddf0a1554f982665e8976bb4c830ecc71093968f61c9c9423d70885a4d406183c3883743ebb7525024c7220b4017510abf4ca60b8a3308476c39843252422be1a3c32ca2c12cd874e1174a8ff388618b3ae29f5d1af062a619887d111708bc3507198c6196824065d0ee618ecc25624a8a4d372fa6b10483d4576a096b92fa0ea91dded271b5bc0fd837b69e72608b2028d7cfba9de18df915695d13d73eef49cdb485770f59d4095d0db298793e48e1da6a2314c811555b49287d0605a0de86343c73b58b8c33600abf05c5ff11eee8c97ef7e824218317079e33c0833db5d454872640479920a6c1ace5b3ae4217a28f3e64cdc5f16d7f46d84839ca9357cea4c631b46e00ddb93cbdb30765d920175cf16782fcbb8d81e4e710df63f06db56058d2d3b86854b5a3f9fb2c14f65c2454dd44c1043d4d6f53c824fe07bc0923dbfced8",
                ipCdiPrivateKey = "c7a0e9394dbed945ec1a8ea160fce0901ce3867f3c0d969318b9c0f777ccb2f4"
            };

            UInt64 expiry = 1234567;
            try
            {
                var result = Idiss.ValidateRequest(global, ipInfo, arsInfos, request);
                var expected = new AccountAddress("3XqeZafxX5vpcUb6hLW98gYwdMxAsPWG5CkkijW98ZMptvej3y");
                Assert.AreEqual(result, expected);
                var idCreation = Idiss.CreateIdentityObject(ipInfo, alist, request, expiry, ipKeys);
                Assert.AreEqual(request.idObjectRequest.value.choiceArData.threshold,
                                idCreation.arRecord.value.revocationThreshold,
                                "AR record does not have the correct anonymity revocation threshold.");
            }
            catch (RequestValidationException e)
            {
                Assert.Fail(String.Format("Validation failed: {0}", e.Message));
            }
            catch (IdentityCreationException e)
            {
                Assert.Fail(String.Format("Identity creation failed: {0}", e.Message));
            }
        }

        [TestMethod]
        public void TestValidationAndIdCreationV1()
        {
            StreamReader r = new StreamReader("../../../../data/global.json");
            string globalStr = r.ReadToEnd();
            var global = JsonSerializer.Deserialize<Versioned<GlobalContext>>(globalStr);
            StreamReader r2 = new StreamReader("../../../../data/valid_request_v1.json");
            string requestStr = r2.ReadToEnd();
            var request = JsonSerializer.Deserialize<IdObjectRequestV1>(requestStr);
            StreamReader r3 = new StreamReader("../../../../data/anonymity_revokers.json");
            string arsInfosStr = r3.ReadToEnd();
            var arsInfos = JsonSerializer.Deserialize<Versioned<Dictionary<string, ArInfo>>>(arsInfosStr);
            StreamReader r4 = new StreamReader("../../../../data/identity_provider.pub.json");
            string ipInfoStr = r4.ReadToEnd();
            var ipInfo = JsonSerializer.Deserialize<Versioned<IpInfo>>(ipInfoStr);
            var options = new JsonSerializerOptions();
            options.Converters.Add(new DictionaryConverter());
            options.Converters.Add(new YearMonthConverter());

            StreamReader r5 = new StreamReader("../../../../data/alist.json");
            string alistStr = r5.ReadToEnd();
            var alist = JsonSerializer.Deserialize<AttributeList>(alistStr, options);

            var ipKeys = new IpPrivateKeys
            {
                ipPrivateKey = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e2c7551ad2184d5503fae6f827b2c4ead26ced6d2cc77d9afb7cfa3a6b4079ded59548320ec6cb2e8e2832f05978a3e78194562dd8db40c16104def1460c8746a4b51a6eef6d2d399cb61deaf44a2e051fc789607e62ca18de0b43c0993eb9c8b0f948cfd129acdc5069d388ecd225fd265c3c5843174ef683a4ce7cb132721c452126c3507884c646365177e18a91df68637dcd582263c5de3a23b41acc2d3925649d4741327271841d9ea328ad389d1697d47ad2f62600b35fa0d5b8dd3c2b86f1a786b2a0074933b45c61109fe8d47ccd8fc7334dc925facf2eb9ccf850d7a63fa089edb6acf70b9f463d96b6f5ad3c4a74efe7df749d6b8ea9d95ee9dfc5a587d7d07c484b26dac3c2add6201d08084af9293d9ac3feec5607e8df365816d14a48f512e8d17091db0e451332706523005ae2ee9bc444df94e805d300666f8293484e951df8b8ed167bf9cafa865c41532d900281b81d7484521f2482159b66bbd958441358bf16733f0dd63c8869a2c8f6778d294f2e437c2b257f18deb5c0114ba156af66ccb315ca1c8b817ccbf1c440667c03790b555cb1489328fdd6d38e52d3df8b9b3fe003a1f76c2c56ea7f5acdf2bd0ef2dfbbe1fd03234935e235004c8666b7dc5eebf305965fc880400d1a6ddcb993631ec14ab316849d8fbf426bbae261d82810fd6f19cd0f1626f57af3d66c3ac9e68215effd94a8a85dd1c70ee71b4c591d0d06cf19ff0658f303201788a10629ecd04b4b9437eec09d20d5245efa68fe00d7ea756ad5c928c2b5a2504672a0bc87498deb77345ad1105fa399976ab42441b90454d44c0a4e9173accd1b7ef81d20af25518e885310e47cb4ea7af6cd3a4c4e72affd0efcb830c8a200a6bf03c6bfa13d648ee937ffa24545b1e3081b23994c435513ec6f705fa8b6d9f974b1d0cb23700c362362ddf0a1554f982665e8976bb4c830ecc71093968f61c9c9423d70885a4d406183c3883743ebb7525024c7220b4017510abf4ca60b8a3308476c39843252422be1a3c32ca2c12cd874e1174a8ff388618b3ae29f5d1af062a619887d111708bc3507198c6196824065d0ee618ecc25624a8a4d372fa6b10483d4576a096b92fa0ea91dded271b5bc0fd837b69e72608b2028d7cfba9de18df915695d13d73eef49cdb485770f59d4095d0db298793e48e1da6a2314c811555b49287d0605a0de86343c73b58b8c33600abf05c5ff11eee8c97ef7e824218317079e33c0833db5d454872640479920a6c1ace5b3ae4217a28f3e64cdc5f16d7f46d84839ca9357cea4c631b46e00ddb93cbdb30765d920175cf16782fcbb8d81e4e710df63f06db56058d2d3b86854b5a3f9fb2c14f65c2454dd44c1043d4d6f53c824fe07bc0923dbfced8",
                ipCdiPrivateKey = "c7a0e9394dbed945ec1a8ea160fce0901ce3867f3c0d969318b9c0f777ccb2f4"
            };

            try
            {
                Idiss.ValidateRequestV1(global, ipInfo, arsInfos, request);
                var expected = new AccountAddress("3XqeZafxX5vpcUb6hLW98gYwdMxAsPWG5CkkijW98ZMptvej3y");
                var idCreation = Idiss.CreateIdentityObjectV1(ipInfo, alist, request, ipKeys);
                Assert.AreEqual(request.idObjectRequest.value.choiceArData.threshold,
                                idCreation.arRecord.value.revocationThreshold,
                                "AR record does not have the correct anonymity revocation threshold.");
            }
            catch (RequestValidationException e)
            {
                Assert.Fail(String.Format("Validation failed: {0}", e.Message));
            }
            catch (IdentityCreationException e)
            {
                Assert.Fail(String.Format("Identity creation failed: {0}", e.Message));
            }
        }

        [TestMethod]
        public void TestRecoveryValidation()
        {
            StreamReader r = new StreamReader("../../../../data/global.json");
            string globalStr = r.ReadToEnd();
            var global = JsonSerializer.Deserialize<Versioned<GlobalContext>>(globalStr);
            StreamReader r2 = new StreamReader("../../../../data/id_recovery_request.json");
            string requestStr = r2.ReadToEnd();
            var request = JsonSerializer.Deserialize<IdRecoveryWrapper>(requestStr);
            StreamReader r3 = new StreamReader("../../../../data/identity_provider.pub.json");
            string ipInfoStr = r3.ReadToEnd();
            var ipInfo = JsonSerializer.Deserialize<Versioned<IpInfo>>(ipInfoStr);

            var ipKeys = new IpPrivateKeys
            {
                ipPrivateKey = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000001e2c7551ad2184d5503fae6f827b2c4ead26ced6d2cc77d9afb7cfa3a6b4079ded59548320ec6cb2e8e2832f05978a3e78194562dd8db40c16104def1460c8746a4b51a6eef6d2d399cb61deaf44a2e051fc789607e62ca18de0b43c0993eb9c8b0f948cfd129acdc5069d388ecd225fd265c3c5843174ef683a4ce7cb132721c452126c3507884c646365177e18a91df68637dcd582263c5de3a23b41acc2d3925649d4741327271841d9ea328ad389d1697d47ad2f62600b35fa0d5b8dd3c2b86f1a786b2a0074933b45c61109fe8d47ccd8fc7334dc925facf2eb9ccf850d7a63fa089edb6acf70b9f463d96b6f5ad3c4a74efe7df749d6b8ea9d95ee9dfc5a587d7d07c484b26dac3c2add6201d08084af9293d9ac3feec5607e8df365816d14a48f512e8d17091db0e451332706523005ae2ee9bc444df94e805d300666f8293484e951df8b8ed167bf9cafa865c41532d900281b81d7484521f2482159b66bbd958441358bf16733f0dd63c8869a2c8f6778d294f2e437c2b257f18deb5c0114ba156af66ccb315ca1c8b817ccbf1c440667c03790b555cb1489328fdd6d38e52d3df8b9b3fe003a1f76c2c56ea7f5acdf2bd0ef2dfbbe1fd03234935e235004c8666b7dc5eebf305965fc880400d1a6ddcb993631ec14ab316849d8fbf426bbae261d82810fd6f19cd0f1626f57af3d66c3ac9e68215effd94a8a85dd1c70ee71b4c591d0d06cf19ff0658f303201788a10629ecd04b4b9437eec09d20d5245efa68fe00d7ea756ad5c928c2b5a2504672a0bc87498deb77345ad1105fa399976ab42441b90454d44c0a4e9173accd1b7ef81d20af25518e885310e47cb4ea7af6cd3a4c4e72affd0efcb830c8a200a6bf03c6bfa13d648ee937ffa24545b1e3081b23994c435513ec6f705fa8b6d9f974b1d0cb23700c362362ddf0a1554f982665e8976bb4c830ecc71093968f61c9c9423d70885a4d406183c3883743ebb7525024c7220b4017510abf4ca60b8a3308476c39843252422be1a3c32ca2c12cd874e1174a8ff388618b3ae29f5d1af062a619887d111708bc3507198c6196824065d0ee618ecc25624a8a4d372fa6b10483d4576a096b92fa0ea91dded271b5bc0fd837b69e72608b2028d7cfba9de18df915695d13d73eef49cdb485770f59d4095d0db298793e48e1da6a2314c811555b49287d0605a0de86343c73b58b8c33600abf05c5ff11eee8c97ef7e824218317079e33c0833db5d454872640479920a6c1ace5b3ae4217a28f3e64cdc5f16d7f46d84839ca9357cea4c631b46e00ddb93cbdb30765d920175cf16782fcbb8d81e4e710df63f06db56058d2d3b86854b5a3f9fb2c14f65c2454dd44c1043d4d6f53c824fe07bc0923dbfced8",
                ipCdiPrivateKey = "c7a0e9394dbed945ec1a8ea160fce0901ce3867f3c0d969318b9c0f777ccb2f4"
            };

            try
            {
                long timestamp = Convert.ToInt64(request.idRecoveryRequest.value.timestamp);
                var idpTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
                Idiss.ValidateRecoveryRequest(global, ipInfo, request, idpTime);
            }
            catch (RequestValidationException e)
            {
                Assert.Fail(String.Format("Valid ID recovery request validation failed: {0}", e.Message));
            }

            try
            {
                long timestamp = Convert.ToInt64(request.idRecoveryRequest.value.timestamp + IdissLib.Idiss.TimestampDelta + 1);
                var idpTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
                Idiss.ValidateRecoveryRequest(global, ipInfo, request, idpTime);
                Assert.Fail("ID recovery request with invalid timestamp did not fail");
            }
            catch (RequestValidationException e)
            {
                Assert.AreEqual(e.Message, "Invalid timestamp.");
            }

            try
            {
                var invalidRequest = request;
                long timestamp = Convert.ToInt64(request.idRecoveryRequest.value.timestamp);
                var idpTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
                invalidRequest.idRecoveryRequest.value.timestamp += 1;
                Idiss.ValidateRecoveryRequest(global, ipInfo, request, idpTime);
                Assert.Fail("ID recovery request with invalid proof did not fail");
            }
            catch (RequestValidationException)
            {
                // Validation failed as expected.
            }
        }
    }
}
