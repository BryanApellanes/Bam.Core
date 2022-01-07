using Bam.Net.CommandLine;
using Bam.Net.Data;
using Bam.Net.Data.SQLite;
using Bam.Net.Encryption;
using Bam.Net.Testing;
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
    public class ServerKeySetDataManagerShould
    {

        [UnitTest]
        public void CreateServerKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager keySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = keySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;

            Expect.IsNotNullOrEmpty(serverKeySet.RsaKey);
            Expect.IsNotNullOrEmpty(serverKeySet.Identifier);
            Expect.IsNotNullOrEmpty(serverKeySet.Secret);
            Expect.IsNullOrEmpty(serverKeySet.AesKey);
            Expect.IsNullOrEmpty(serverKeySet.AesIV);

            Expect.IsNotNullOrEmpty(serverKeySet.ServerHostName);
            Expect.IsNotNullOrEmpty(serverKeySet.ApplicationName);

            Expect.AreEqual(testClientHostName, serverKeySet.ClientHostName);            
        }

        [UnitTest]
        public void CreateClientKeySetForServerKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateClientKeySetForServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;

            Expect.AreEqual(serverKeySet.Identifier, clientKeySet.Identifier);
            Expect.IsFalse(clientKeySet.GetIsInitialized());
            Expect.IsNullOrEmpty(clientKeySet.AesKey);
            Expect.IsNullOrEmpty(clientKeySet.AesIV);
        }

        [UnitTest]
        public void SetServerAesKey()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(SetServerAesKey)}_Test_ServerKeySetData"));
            IClientKeySetDataManager clientKeySetDataManager = new ClientKeySetDataManager(CreateTestDatabase($"{nameof(SetServerAesKey)}_Test_ClientKeySetData"));

            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;

            IAesKeyExchange aesKeyExchange = clientKeySetDataManager.CreateAesKeyExchangeAsync(clientKeySet).Result;
            serverKeySet = serverKeySetDataManager.SetServerAesKeyAsync(aesKeyExchange).Result;

            Expect.IsNotNullOrEmpty(serverKeySet.RsaKey);
            Expect.IsNotNull(serverKeySet.Identifier);
            Expect.IsNotNullOrEmpty(serverKeySet.AesKey);
            Expect.IsNotNullOrEmpty(serverKeySet.AesIV);
            Expect.AreEqual(clientKeySet.AesKey, serverKeySet.AesKey);
            Expect.AreEqual(clientKeySet.AesIV, serverKeySet.AesIV);

            Expect.IsNotNullOrEmpty(serverKeySet.ServerHostName);
            Expect.IsNotNullOrEmpty(serverKeySet.ApplicationName);

            Expect.AreEqual(testClientHostName, serverKeySet.ClientHostName);
        }
        
        [UnitTest]
        public void RetrieveServerKeySetForPublicKey()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(RetrieveServerKeySetForPublicKey)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IServerKeySet retreievedServerKeySet = serverKeySetDataManager.RetrieveServerKeySetForPublicKeyAsync(clientKeySet.PublicKey).Result;
            
            Expect.AreEqual(serverKeySet.Identifier, retreievedServerKeySet.Identifier);
            Expect.AreEqual(serverKeySet.Secret, retreievedServerKeySet.Secret);
            Expect.AreEqual(serverKeySet.ApplicationName, retreievedServerKeySet.ApplicationName);
            Expect.AreEqual(serverKeySet.RsaKey, retreievedServerKeySet.RsaKey);
            Expect.AreEqual(serverKeySet.AesKey, retreievedServerKeySet.AesKey);
            Expect.AreEqual(serverKeySet.AesIV, retreievedServerKeySet.AesIV);
            Expect.AreEqual(serverKeySet.ServerHostName, retreievedServerKeySet.ServerHostName);
            Expect.AreEqual(serverKeySet.ClientHostName, retreievedServerKeySet.ClientHostName);
        }

        [UnitTest]
        public void RetrieveServerKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(RetrieveServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = serverKeySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IServerKeySet retreievedServerKeySet = serverKeySetDataManager.RetrieveServerKeySetAsync(serverKeySet.Identifier).Result;
            
            Expect.AreEqual(serverKeySet.Identifier, retreievedServerKeySet.Identifier);
            Expect.AreEqual(serverKeySet.Secret, retreievedServerKeySet.Secret);
            Expect.AreEqual(serverKeySet.ApplicationName, retreievedServerKeySet.ApplicationName);
            Expect.AreEqual(serverKeySet.RsaKey, retreievedServerKeySet.RsaKey);
            Expect.AreEqual(serverKeySet.AesKey, retreievedServerKeySet.AesKey);
            Expect.AreEqual(serverKeySet.AesIV, retreievedServerKeySet.AesIV);
            Expect.AreEqual(serverKeySet.ServerHostName, retreievedServerKeySet.ServerHostName);
            Expect.AreEqual(serverKeySet.ClientHostName, retreievedServerKeySet.ClientHostName);
        }

        [UnitTest]
        public void GetSecretExchange()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager serverKeySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(GetSecretExchange)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = serverKeySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;

            Expect.IsNotNullOrEmpty(serverKeySet.Secret);

            ISecretExchange secretExchange = serverKeySetDataManager.GetSecretExchangeAsync(serverKeySet).Result;

            Expect.AreEqual(serverKeySet.Identifier, secretExchange.Identifier);
            Expect.AreEqual(serverKeySet.ServerHostName, secretExchange.ServerHostName);
            Expect.AreEqual(serverKeySet.ClientHostName, secretExchange.ClientHostName);
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
