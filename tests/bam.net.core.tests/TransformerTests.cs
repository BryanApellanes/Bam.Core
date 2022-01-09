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
        public void BsonTransformerTest()
        {
            BsonTransformer<TestMonkey> transformer = new BsonTransformer<TestMonkey>();
            TestMonkey testMonkey = new TestMonkey()
            { 
                Name = "Bson Fred"
            };

            byte[] bson = transformer.Transform(testMonkey);

            TestMonkey decoded = transformer.GetReverseTransformer().ReverseTransform(bson);

            Expect.AreEqual(testMonkey.Name, decoded.Name);
        }

        [UnitTest]
        public void JsonTransformerTest()
        {
            JsonTransformer<TestMonkey> transformer = new JsonTransformer<TestMonkey>();
            TestMonkey testMonkey = new TestMonkey()
            {
                Name = "Fred"
            };

            string json = transformer.Transform(testMonkey);
            
            TestMonkey decoded = transformer.GetReverseTransformer().ReverseTransform(json);

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
        public void AesBase64TransformerTest()
        {
            AesKeyVectorPair aesKeyVectorPair = new AesKeyVectorPair();
            AesBase64Transformer aesBase64Transformer = new AesBase64Transformer(aesKeyVectorPair);

            string testData = "this is the test data";
            string base64Cipher = aesBase64Transformer.Transform(testData);

            Expect.IsFalse(testData.Equals(base64Cipher));

            string decipherd = aesBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);

            Equals(testData, decipherd);
        }

        [UnitTest]
        public void RsaByteTransformerTest()
        {
            RsaPublicPrivateKeyPair rsaKey = new RsaPublicPrivateKeyPair();
            RsaByteTransformer rsaByteTransformer = new RsaByteTransformer(rsaKey);

            string testData = "this is the test data";
            byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);
            byte[] cipher = rsaByteTransformer.Transform(testDataBytes);

            Expect.IsFalse(testDataBytes.Length == cipher.Length);

            string base64Data = Convert.ToBase64String(testDataBytes);
            string base64Cipher = Convert.ToBase64String(cipher);

            Expect.IsNotNullOrEmpty(base64Data);
            Expect.IsNotNullOrEmpty(base64Cipher);
            Expect.IsFalse(base64Data.Equals(base64Cipher));

            byte[] deciphered = rsaByteTransformer.GetReverseTransformer().ReverseTransform(cipher);
            string decipheredText = Encoding.UTF8.GetString(deciphered);

            Expect.AreEqual(testData, decipheredText);
        }

        [UnitTest]
        public void RsaBase64TransformerTest()
        {
            RsaPublicPrivateKeyPair rsaKey = new RsaPublicPrivateKeyPair();
            RsaBase64Transformer rsaBase64Transformer = new RsaBase64Transformer(rsaKey);

            string testData = "this is the test data";
            string base64Cipher = rsaBase64Transformer.Transform(testData);

            Expect.IsFalse(testData.Length == base64Cipher.Length);
            Expect.IsNotNullOrEmpty(base64Cipher);
            Expect.IsFalse(testData.Equals(base64Cipher));

            string deciphered = rsaBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);

            Expect.AreEqual(testData, deciphered);
        }

        [UnitTest]
        public void GZipTransformerTest()
        {
            GZipByteTransformer gzipByteTransformer = new GZipByteTransformer();
            string testData = "this is the test data. 0000000000000000 111111111111111 2222222222";
            byte[] testBytes = Encoding.UTF8.GetBytes(testData);
            byte[] zipped = gzipByteTransformer.Transform(testBytes);

            Expect.IsTrue(zipped.Length < testBytes.Length);

            byte[] unzipped = gzipByteTransformer.GetReverseTransformer().ReverseTransform(zipped);
            string decoded = Encoding.UTF8.GetString(unzipped);

            Expect.AreEqual(testData, decoded);
        }

        [UnitTest]
        public void ZipEncrypted()
        {
            AesKeyVectorPair aesKey1 = new AesKeyVectorPair();
            AesByteTransformer aesByteTransformer = new AesByteTransformer(aesKey1);
            GZipByteTransformer gZipByteTransformer = new GZipByteTransformer();

            string testData = "this is the test data.";
            byte[] testBytes = Encoding.UTF8.GetBytes(testData);

            byte[] encrypted = aesByteTransformer.Transform(testBytes);
            byte[] zippedEncrypted = gZipByteTransformer.Transform(encrypted);

            byte[] unzippedEncrypted = gZipByteTransformer.GetReverseTransformer().ReverseTransform(zippedEncrypted);
            byte[] decrypted = aesByteTransformer.GetReverseTransformer().ReverseTransform(unzippedEncrypted);

            string decryptedData = Encoding.UTF8.GetString(decrypted);

            Expect.AreEqual(encrypted, unzippedEncrypted);
            Expect.AreEqual(testData, decryptedData);
        }

        [UnitTest]
        public void ZipAndReverseAesTransform()
        {
            AesKeyVectorPair aesKey1 = new AesKeyVectorPair();
            AesByteTransformer aesByteTransformer = new AesByteTransformer(aesKey1);
            GZipByteTransformer gZipByteTransformer = new GZipByteTransformer();

            List<IValueTransformer<byte[], byte[]>> transformers = new List<IValueTransformer<byte[], byte[]>>();
            transformers.Add(aesByteTransformer);
            transformers.Add(gZipByteTransformer);

            string testData = "this is the test data";
            byte[] testBytes = Encoding.UTF8.GetBytes(testData);

            byte[] transformed = testBytes;
            foreach(IValueTransformer<byte[], byte[]> transformer in transformers)
            {
                transformed = transformer.Transform(transformed);
            }

            List<IValueReverseTransformer<byte[], byte[]>> reverseTransforms = new List<IValueReverseTransformer<byte[], byte[]>>();
            transformers.BackwardsEach(transformer => reverseTransforms.Add(transformer.GetReverseTransformer()));

            byte[] reversed = transformed;
            foreach(IValueReverseTransformer<byte[], byte[]> reverseTransformer in reverseTransforms)
            {
                reversed = reverseTransformer.ReverseTransform(reversed);
            }

            string reversedData = Encoding.UTF8.GetString(reversed);

            Expect.AreEqual(testData, reversedData);
        }

        [UnitTest]
        public void ByteTransformPipelineTransformAndReverse()
        {
            AesKeyVectorPair aesKey1 = new AesKeyVectorPair();
            AesByteTransformer aesByteTransformer = new AesByteTransformer(aesKey1);
            GZipByteTransformer gZipByteTransformer = new GZipByteTransformer();

            ByteTransformerPipeline byteTransformerPipeline = new ByteTransformerPipeline();
            byteTransformerPipeline.Add(aesByteTransformer);
            byteTransformerPipeline.Add(gZipByteTransformer);

            string testData = "this is the test data";
            byte[] testBytes = Encoding.UTF8.GetBytes(testData);

            byte[] transformed = byteTransformerPipeline.Transform(testBytes);
            
            Expect.IsFalse(testBytes.SequenceEqual(transformed));

            byte[] reversedBytes = byteTransformerPipeline.GetReverseTransformer().ReverseTransform(transformed);
            string reversed = Encoding.UTF8.GetString(reversedBytes);

            Expect.AreEqual(testData, reversed);

        }

/*        [UnitTest]
        public void PipelineShouldTransformAndReverse()
        {
            ServiceProxyDataRepository testServiceProxyDataRepository = new ServiceProxyDataRepository();
            SecureChannelSession testSecureChannelSession = new SecureChannelSession(new Instant(), true);
            testSecureChannelSession = testServiceProxyDataRepository.Save(testSecureChannelSession);
            ClientSession testClientSession = testSecureChannelSession.GetClientSession(false);
            testClientSession.InitializeSessionKey();

            ValueTransformerPipeline<TestMonkey> valueTransformerPipeline = new ValueTransformerPipeline<TestMonkey>();
            valueTransformerPipeline.BeforeTransformConverter = new BsonValueConverter<TestMonkey>();
            valueTransformerPipeline.AfterTransformConverter = new Base64ValueConverter();

            AesKeyVectorPair aesKey = new AesKeyVectorPair();
            valueTransformerPipeline.Add(new AesByteTransformer(aesKey));
            valueTransformerPipeline.Add(new GZipByteTransformer());

            TestMonkey testMonkey = new TestMonkey()
            {
                Name = "Bobo",
                TailCount = 3,
            };

            string base64 = valueTransformerPipeline.Transform(testMonkey);

            TestMonkey untransformed = valueTransformerPipeline.GetReverseTransformer().ReverseTransform(base64);

            Expect.AreEqual(testMonkey.Name, untransformed.Name);
        }*/
    }
}
