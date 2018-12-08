namespace org.bouncycastle.est.test
{

	using TestCase = junit.framework.TestCase;
	using JsseDefaultHostnameAuthorizer = org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer;

	public class HostNameAuthorizerMatchTest : TestCase
	{
		public virtual void testWildcardMatcher()
		{

			object[][] v = new object[][]
			{
				new object[] {"Exact", "a.foo.com", "a.foo.com", true},
				new object[] {"Left most", "abacus.foo.com", "*s.foo.com", true},
				new object[] {"Invalid 1", "localhost.cisco.com", "localhost.*.com", true},
				new object[] {"Invalid 2", "localhost.cisco.com", "localhost.cisco.*", false},
				new object[] {"Invalid 3 - subdomain", "localhost.cisco.com", "*.com", false},
				new object[] {"Invalid 4", "localhost.cisco.com", "*.localhost.cisco.com", false},
				new object[] {"Invalid 5", "localhost.cisco.com", "*", false},
				new object[] {"Invalid 6", "localhost.cisco.com", "localhost*.cisco.com", true},
				new object[] {"Invalid 7", "localhost.cisco.com", "*localhost.cisco.com", false},
				new object[] {"Invalid 8", "localhost.cisco.com", "local*host.cisco.com", true},
				new object[] {"Invalid 9", "localhost.cisco.com", "localhost.c*.com", true},
				new object[] {"Invalid 10", "localhost.cisco.com", "localhost.*o.com", true},
				new object[] {"Invalid 11", "localhost.cisco.com", "localhost.c*o.com", true},
				new object[] {"Invalid 12", "localhost.cisco.com", "*..com", false},
				new object[] {"Invalid 13", "foo.example.com", "*.example.com", true},
				new object[] {"Invalid 14", "bar.foo.example.com", "*.example.com", false},
				new object[] {"Invalid 15", "example.com", "*.example.com", false},
				new object[] {"Invalid 16", "foobaz.example.com", "b*z.example.com", false},
				new object[] {"Invalid 17", "foobaz.example.com", "ob*z.example.com", false},
				new object[] {"Valid", "foobaz.example.com", "foob*z.example.com", true}
			};

			foreach (object[] j in v)
			{
				assertEquals(j[0].ToString(), j[3], JsseDefaultHostnameAuthorizer.isValidNameMatch((string)j[1], (string)j[2], null));
			}
		}

		public virtual void testWildcardPublicSuffix()
		{

			object[][] v = new object[][]
			{
				new object[] {"Invalid 3", "localhost.cisco.com", "*.com", false},
				new object[] {"Invalid 9", "localhost.cisco.com", "localhost.c*.com", false},
				new object[] {"Invalid 10", "localhost.cisco.com", "localhost.*o.com", false},
				new object[] {"Invalid 11", "localhost.cisco.com", "localhost.c*o.com", false}
			};

			HashSet<string> suf = new HashSet<string>();
			suf.add(".com");

			foreach (object[] j in v)
			{
				try
				{
					assertEquals(j[0].ToString(), j[3], JsseDefaultHostnameAuthorizer.isValidNameMatch((string)j[1], (string)j[2], suf));
					fail("known suffix not caught");
				}
				catch (IOException)
				{
					// expected
				}
			}
		}
	}

}