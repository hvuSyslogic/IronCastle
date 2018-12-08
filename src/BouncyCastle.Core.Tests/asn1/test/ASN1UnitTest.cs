namespace org.bouncycastle.asn1.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public abstract class ASN1UnitTest : SimpleTest
	{
		public virtual void checkMandatoryField(string name, ASN1Encodable expected, ASN1Encodable present)
		{
			if (!expected.Equals(present))
			{
				fail(name + " field doesn't match.");
			}
		}

		public virtual void checkMandatoryField(string name, string expected, string present)
		{
			if (!expected.Equals(present))
			{
				fail(name + " field doesn't match.");
			}
		}

		public virtual void checkMandatoryField(string name, byte[] expected, byte[] present)
		{
			if (!areEqual(expected, present))
			{
				fail(name + " field doesn't match.");
			}
		}

		public virtual void checkMandatoryField(string name, int expected, int present)
		{
			if (expected != present)
			{
				fail(name + " field doesn't match.");
			}
		}

		public virtual void checkOptionalField(string name, ASN1Encodable expected, ASN1Encodable present)
		{
			if (expected != null)
			{
				if (!expected.Equals(present))
				{
					fail(name + " field doesn't match.");
				}
			}
			else if (present != null)
			{
				fail(name + " field found when none expected.");
			}
		}

		public virtual void checkOptionalField(string name, string expected, string present)
		{
			if (!string.ReferenceEquals(expected, null))
			{
				if (!expected.Equals(present))
				{
					fail(name + " field doesn't match.");
				}
			}
			else if (!string.ReferenceEquals(present, null))
			{
				fail(name + " field found when none expected.");
			}
		}

		public virtual void checkOptionalField(string name, BigInteger expected, BigInteger present)
		{
			if (expected != null)
			{
				if (!expected.Equals(present))
				{
					fail(name + " field doesn't match.");
				}
			}
			else if (present != null)
			{
				fail(name + " field found when none expected.");
			}
		}


	}

}