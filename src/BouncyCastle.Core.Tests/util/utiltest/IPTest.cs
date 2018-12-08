namespace org.bouncycastle.util.utiltest
{
	using TestCase = junit.framework.TestCase;

	public class IPTest : TestCase
	{

		private static readonly string[] validIP4v = new string[] {"0.0.0.0", "255.255.255.255", "192.168.0.0"};

		private static readonly string[] invalidIP4v = new string[] {"0.0.0.0.1", "256.255.255.255", "1", "A.B.C", "1:.4.6.5"};

		private static readonly string[] validIP6v = new string[] {"0:0:0:0:0:0:0:0", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "0:1:2:3:FFFF:5:FFFF:1"};

		private static readonly string[] invalidIP6v = new string[] {"0.0.0.0:1", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFFF"};

		private void testIP(string[] valid, string[] invalid)
		{
			for (int i = 0; i < valid.Length; i++)
			{
				if (!IPAddress.isValid(valid[i]))
				{
					fail("Valid input string not accepted: " + valid[i] + ".");
				}
			}
			for (int i = 0; i < invalid.Length; i++)
			{
				if (IPAddress.isValid(invalid[i]))
				{
					fail("Invalid input string accepted: " + invalid[i] + ".");
				}
			}
		}

		public virtual string getName()
		{
			return "IPTest";
		}

		public virtual void testIPv4()
		{
			testIP(validIP4v, invalidIP4v);
		}

		public virtual void testIPv6()
		{
			testIP(validIP6v, invalidIP6v);
		}
	}

}