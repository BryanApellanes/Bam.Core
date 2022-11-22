using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Bam.Net.CommandLine;
using Bam.Net.Data;
using Bam.Net.Data.SQLite;
using Bam.Net.Encryption;
using Bam.Net.Testing;
using Bam.Net.Testing.Unit;

namespace Bam.Net.Tests
{
    public class EncryptedDictionaryTests
    {
        [UnitTest]
        public void DictionaryShouldEncryptAndDecryptAes()
        {
            AesKeyVectorPair aesKeyVectorPair = new AesKeyVectorPair();
            AesEncryptor aesEncryptor = new AesEncryptor(aesKeyVectorPair);
            AesDecryptor aesDecryptor = new AesDecryptor(aesKeyVectorPair);

            EncryptedDictionary encryptedDictionary = new EncryptedDictionary(aesEncryptor);
            encryptedDictionary["key1"] = "value1";
            encryptedDictionary["key2"] = "value2";
            encryptedDictionary["key3"] = "value3";
            encryptedDictionary["key4"] = "value4";
            encryptedDictionary["key5"] = "value5";

            string value1 = encryptedDictionary["key1"];
            Message.PrintLine("value1 = {0}", value1);

            string output = encryptedDictionary.ToString();

            Message.PrintLine(output);

            DecryptedDictionary decryptedDictionary = DecryptedDictionary.FromString(aesDecryptor, output);
            Expect.IsTrue(decryptedDictionary.ContainsKey("key1"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key2"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key3"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key4"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key5"));

            Expect.AreEqual("value1", decryptedDictionary["key1"]);
            Expect.AreEqual("value2", decryptedDictionary["key2"]);
            Expect.AreEqual("value3", decryptedDictionary["key3"]);
            Expect.AreEqual("value4", decryptedDictionary["key4"]);
            Expect.AreEqual("value5", decryptedDictionary["key5"]);
        }

        [UnitTest]
        public void DictionaryShouldEncryptAndDecryptRsa()
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = new RsaPublicPrivateKeyPair();
            RsaEncryptor rsaEncryptor = new RsaEncryptor(rsaPublicPrivateKeyPair);
            RsaDecryptor rsaDecryptor = new RsaDecryptor(rsaPublicPrivateKeyPair);

            EncryptedDictionary encryptedDictionary = new EncryptedDictionary(rsaEncryptor);
            encryptedDictionary["key1"] = "value1";
            encryptedDictionary["key2"] = "value2";
            encryptedDictionary["key3"] = "value3";
            encryptedDictionary["key4"] = "value4";
            encryptedDictionary["key5"] = "value5";

            string value1 = encryptedDictionary["key1"];
            Message.PrintLine("value1 = {0}", value1);

            string output = encryptedDictionary.ToString();

            Message.PrintLine(output);

            DecryptedDictionary decryptedDictionary = DecryptedDictionary.FromString(rsaDecryptor, output);
            Expect.IsTrue(decryptedDictionary.ContainsKey("key1"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key2"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key3"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key4"));
            Expect.IsTrue(decryptedDictionary.ContainsKey("key5"));

            Expect.AreEqual("value1", decryptedDictionary["key1"]);
            Expect.AreEqual("value2", decryptedDictionary["key2"]);
            Expect.AreEqual("value3", decryptedDictionary["key3"]);
            Expect.AreEqual("value4", decryptedDictionary["key4"]);
            Expect.AreEqual("value5", decryptedDictionary["key5"]);
        }
    }
}
