/*
	Copyright © Bryan Apellanes 2015  
*/

using System.Collections.Specialized;
using System.Reflection;
using Bam.Net.ServiceProxy.Encryption;
using Bam.Net.Web;
using Bam.Net.Testing.Unit;
using System.Collections.Generic;
using System.Linq;

namespace Bam.Net.ServiceProxy.Tests
{
    public partial class ServiceProxyTestContainer
    {
        [UnitTest]
        public void GetProxiedMethodsShouldHaveResults()
        {
            MethodInfo[] methods = ServiceProxySystem.GetProxiedMethods(typeof(EncryptedEcho));
            Expect.IsGreaterThan(methods.Length, 0, "expected more than zero methods");
        }

    }
}
