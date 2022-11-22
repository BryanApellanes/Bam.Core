using Bam.Net.CommandLine;
using Bam.Net.Data;
using Bam.Net.Data.SQLite;
using Bam.Net.Encryption;
using Bam.Net.Encryption.Data;
using Bam.Net.Testing.Unit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Net.Tests
{
    public class ClientKeySetDataManagerShould
    {
        [UnitTest]
        public void CreateAesKeyExchangeForClientKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateAesKeyExchangeForClientKeySet)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDatamanager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(CreateAesKeyExchangeForClientKeySet)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IAesKeyExchange aesKeyExchange = clientKeySetDatamanager.CreateAesKeyExchangeAsync(clientKeySet).Result;

            Expect.AreEqual(clientKeySet.PublicKey, aesKeyExchange.PublicKey);
            Expect.IsNotNullOrEmpty(aesKeyExchange.AesKeyCipher);
            Expect.IsNotNullOrEmpty(aesKeyExchange.AesIVCipher);
            Expect.AreEqual(clientKeySet.ClientHostName, aesKeyExchange.ClientHostName);
            Expect.AreEqual(clientKeySet.ServerHostName, aesKeyExchange.ServerHostName);
        }

        [UnitTest]
        public void RetrieveClientKeySetAfterCreatingKeyExchange()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(RetrieveClientKeySetAfterCreatingKeyExchange)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDatamanager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(RetrieveClientKeySetAfterCreatingKeyExchange)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IAesKeyExchange aesKeyExchange = clientKeySetDatamanager.CreateAesKeyExchangeAsync(clientKeySet).Result;

            IClientKeySet retrievedClientKeySet = clientKeySetDatamanager.RetrieveClientKeySetAsync(clientKeySet.Identifier).Result;

            Expect.AreEqual(clientKeySet.Identifier, retrievedClientKeySet.Identifier);
            Expect.AreEqual(clientKeySet.ClientHostName, retrievedClientKeySet.ClientHostName);
            Expect.AreEqual(clientKeySet.ServerHostName, retrievedClientKeySet.ServerHostName);
            Expect.AreEqual(clientKeySet.AesKey, retrievedClientKeySet.AesKey);
            Expect.AreEqual(clientKeySet.AesIV, retrievedClientKeySet.AesIV);
            Expect.AreEqual(clientKeySet.GetIsInitialized(), retrievedClientKeySet.GetIsInitialized());
            Expect.IsTrue(retrievedClientKeySet.GetIsInitialized());
        }

        [UnitTest]
        public void CreateAesKeyExchangeWithoutDuplicatingClientKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateAesKeyExchangeForClientKeySet)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDatamanager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(CreateAesKeyExchangeForClientKeySet)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySetOne = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IClientKeySet clientKeySetTwo = clientKeySetOne.CopyAsNew<ClientKeySet>();

            Expect.AreEqual(clientKeySetOne.Identifier, clientKeySetTwo.Identifier);

            IAesKeyExchange aesKeyExchangeOne = clientKeySetDatamanager.CreateAesKeyExchangeAsync(clientKeySetOne).Result;
            IAesKeyExchange aesKeyExchangeTwo = clientKeySetDatamanager.CreateAesKeyExchangeAsync(clientKeySetTwo).Result;

            int count = clientKeySetDatamanager.EncryptionDataRepository.Query<ClientKeySet>(where => where.Identifier == clientKeySetOne.Identifier).Count();
            Expect.AreEqual(1, count);
        }

        [UnitTest]
        public void RetreiveClientKeySetForPublicKey()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(RetreiveClientKeySetForPublicKey)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDatamanager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(RetreiveClientKeySetForPublicKey)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            clientKeySetDatamanager.SaveClientKeySetAsync(clientKeySet).Wait();

            IClientKeySet retrievedClientKeySet = clientKeySetDatamanager.RetrieveClientKeySetForPublicKeyAsync(clientKeySet.PublicKey).Result;

            Expect.IsNullOrEmpty(clientKeySet.AesKey);
            Expect.IsNullOrEmpty(clientKeySet.AesIV);
            Expect.IsNullOrEmpty(retrievedClientKeySet.AesKey);
            Expect.IsNullOrEmpty(retrievedClientKeySet.AesIV);

            Expect.AreEqual(clientKeySet.Identifier, retrievedClientKeySet.Identifier);
            Expect.AreEqual(clientKeySet.ClientHostName, retrievedClientKeySet.ClientHostName);
            Expect.AreEqual(clientKeySet.ServerHostName, retrievedClientKeySet.ServerHostName);

            Expect.AreEqual(clientKeySet.GetIsInitialized(), retrievedClientKeySet.GetIsInitialized());
            Expect.IsFalse(retrievedClientKeySet.GetIsInitialized());
        }

        [UnitTest]
        public void SaveClientKeySetWithoutDuplicating()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(SaveClientKeySetWithoutDuplicating)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDataManager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(SaveClientKeySetWithoutDuplicating)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;

            Expect.IsNotNullOrEmpty(serverKeySet.Secret);

            ISecretExchange secretExchange = serverKeySetDataManager.GetSecretExchangeAsync(serverKeySet).Result;

            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IClientKeySet clientKeySetCopy = clientKeySet.CopyAsNew<ClientKeySet>();

            IClientKeySet savedClientKeySet = clientKeySetDataManager.SaveClientKeySetAsync(clientKeySet).Result;
            IClientKeySet savedAgainClientKeySet = clientKeySetDataManager.SaveClientKeySetAsync(clientKeySetCopy).Result;

            int count = clientKeySetDataManager.EncryptionDataRepository.Query<ClientKeySet>(where => where.Identifier == clientKeySet.Identifier).Count();
            Expect.AreEqual(1, count);
        }

        [UnitTest]
        public void SetSecret()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(SetSecret)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDataManager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(SetSecret)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;

            IAesKeyExchange aesKeyExchange = clientKeySetDataManager.CreateAesKeyExchangeAsync(clientKeySet).Result;
            serverKeySet = serverKeySetDataManager.SetServerAesKeyAsync(aesKeyExchange).Result;

            Expect.IsTrue(serverKeySet.GetIsAesInitialized());
            Expect.IsTrue(clientKeySet.GetIsInitialized());
            Expect.AreEqual(serverKeySet.AesKey, clientKeySet.AesKey);
            Expect.AreEqual(serverKeySet.AesIV, clientKeySet.AesIV);
            Expect.IsNotNullOrEmpty(serverKeySet.Secret);

            ISecretExchange secretExchange = serverKeySetDataManager.GetSecretExchangeAsync(serverKeySet).Result;
            IClientKeySet savedClientKeySet = clientKeySetDataManager.SaveClientKeySetAsync(clientKeySet).Result;            

            Expect.IsNullOrEmpty(savedClientKeySet.Secret);

            IClientKeySet secretSetClientKeySet = clientKeySetDataManager.SetSecret(secretExchange).Result;

            Expect.AreEqual(secretSetClientKeySet.Secret, serverKeySet.Secret);
        }

        private Database CreateTestDatabase(string testName)
        {
            string fileName = Path.GetFileNameWithoutExtension(Assembly.GetExecutingAssembly().GetFileInfo().FullName);
            SQLiteDatabase db = new SQLiteDatabase(Path.Combine($"{BamHome.DataPath}", fileName), testName);
            Message.PrintLine("{0}: SQLite database: {1}", testName, db.DatabaseFile.FullName);
            return db;
        }
    }
}
