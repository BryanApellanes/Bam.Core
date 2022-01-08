using Bam.Net.Encryption;
using Bam.Net.ServiceProxy.Data;
using Bam.Net.ServiceProxy.Data.Dao.Repository;
using Bam.Net.ServiceProxy.Secure;
using Bam.Net.Testing.Unit;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Net.Tests
{
    public class TransformerTests : CommandLineTool
    {
        [UnitTest]
        public void JsonTransformerTest()
        {
            JsonTransformer<TestMonkey> transformer = new JsonTransformer<TestMonkey>();
            TestMonkey testMonkey = new TestMonkey()
            {
                Name = "Fred"
            };

            string json = transformer.Transform(testMonkey);
            IValueReverseTransformer<string, TestMonkey> untransformer = transformer.GetReverseTransformer();

            TestMonkey decoded = untransformer.ReverseTransform(json);

            Expect.AreEqual(testMonkey.Name, decoded.Name);
        }

        [UnitTest]
        public void Base64TransformerTest()
        {
            Base64Transformer base64Transformer = new Base64Transformer();
            SecureRandom secureRandom = new SecureRandom();
            byte[] randomBytes = secureRandom.GenerateSeed(64);

            string encoded = base64Transformer.Transform(randomBytes);

            IValueReverseTransformer<string, byte[]> base64Untransformer = base64Transformer.GetReverseTransformer();
            byte[] decoded = base64Untransformer.ReverseTransform(encoded);
            Expect.AreEqual(randomBytes, decoded);
        }

        [UnitTest]
        public void AesByteTransformerTest()
        {
            AesKeyVectorPair aesKeyVectorPair = new AesKeyVectorPair();
            AesByteTransformer aesByteTransformer = new AesByteTransformer(aesKeyVectorPair);

            string testData = "this is the test data";
            byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);

            byte[] cipherData = aesByteTransformer.Transform(testDataBytes);

            byte[] deciphered = aesByteTransformer.GetReverseTransformer().ReverseTransform(cipherData);

            Expect.AreEqual(testDataBytes, deciphered);
            string decipheredTestData = Encoding.UTF8.GetString(deciphered);
            Expect.AreEqual(testData, decipheredTestData);
        }

        [UnitTest]
        public void PipelineShouldEncodeAndDecode()
        {
            ServiceProxyDataRepository testServiceProxyDataRepository = new ServiceProxyDataRepository();
            SecureChannelSession testSecureChannelSession = new SecureChannelSession(new Instant(), true);
            testSecureChannelSession = testServiceProxyDataRepository.Save(testSecureChannelSession);
            ClientSession testClientSession = testSecureChannelSession.GetClientSession(false);
            testClientSession.InitializeSessionKey();

            ValueTransformerPipeline<TestMonkey> valueTransformerPipeline = new ValueTransformerPipeline<TestMonkey>();
            valueTransformerPipeline.BeforeTransformConverter = new BsonValueConverter<TestMonkey>();
            valueTransformerPipeline.AfterTransformConverter = new Base64ValueConverter();

            valueTransformerPipeline.Add(new GZipByteTransformer());

            TestMonkey testMonkey = new TestMonkey()
            {
                Name = "Bobo",
                TailCount = 3,
            };

            string base64 = valueTransformerPipeline.Transform(testMonkey);

            TestMonkey untransformed = valueTransformerPipeline.GetReverseTransformer().ReverseTransform(base64);

            Expect.AreEqual(testMonkey.Name, untransformed.Name);
        }
    }
}
