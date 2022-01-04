﻿using Bam.Net.CommandLine;
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
    public class KeySetDataManagerShould
    {

        [UnitTest]
        public void CreateServerKeySet()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager keySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = keySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;

            Expect.IsNotNullOrEmpty(serverKeySet.RsaKey);
            Expect.IsNotNull(serverKeySet.Identifier);
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
            IServerKeySetDataManager keySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateClientKeySetForServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = keySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = keySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;

            Expect.AreEqual(serverKeySet.Identifier, clientKeySet.Identifier);
            Expect.IsFalse(clientKeySet.GetIsInitialized());
            Expect.IsNullOrEmpty(clientKeySet.AesKey);
            Expect.IsNullOrEmpty(clientKeySet.AesIV);
        }

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
            IServerKeySetDataManager keySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateClientKeySetForServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = keySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = keySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IServerKeySet retreievedServerKeySet = keySetDataManager.RetrieveServerKeySetForPublicKeyAsync(clientKeySet.PublicKey).Result;
            
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
        public void RetrieveServerKeySetByIdentifier()
        {
            string testClientHostName = "test client hostname";
            IServerKeySetDataManager keySetDataManager = new ServerKeySetDataManager(CreateTestDatabase($"{nameof(CreateClientKeySetForServerKeySet)}_Test_ServerKeySetData"));
            IServerKeySet serverKeySet = keySetDataManager.CreateServerKeySetAsync(testClientHostName).Result;
            IClientKeySet clientKeySet = keySetDataManager.CreateClientKeySetForServerKeySetAsync(serverKeySet).Result;
            IServerKeySet retreievedServerKeySet = keySetDataManager.RetrieveServerKeySetAsync(serverKeySet.Identifier).Result;

            Expect.AreEqual(serverKeySet.Identifier, retreievedServerKeySet.Identifier);
            Expect.AreEqual(serverKeySet.Secret, retreievedServerKeySet.Secret);
            Expect.AreEqual(serverKeySet.ApplicationName, retreievedServerKeySet.ApplicationName);
            Expect.AreEqual(serverKeySet.RsaKey, retreievedServerKeySet.RsaKey);
            Expect.AreEqual(serverKeySet.AesKey, retreievedServerKeySet.AesKey);
            Expect.AreEqual(serverKeySet.AesIV, retreievedServerKeySet.AesIV);
            Expect.AreEqual(serverKeySet.ServerHostName, retreievedServerKeySet.ServerHostName);
            Expect.AreEqual(serverKeySet.ClientHostName, retreievedServerKeySet.ClientHostName);
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
