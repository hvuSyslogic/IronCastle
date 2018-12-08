namespace org.bouncycastle.asn1.test
{
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class ObjectIdentifierTest : SimpleTest
	{
		public override string getName()
		{
			return "ObjectIdentifier";
		}

		public override void performTest()
		{
			// exercise the object cache
			for (int i = 0; i < 100; i++)
			{
				for (int j = 0; j < 100; j++)
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid1 = new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.1." + i + "." + j);
					ASN1ObjectIdentifier oid1 = new ASN1ObjectIdentifier("1.1." + i + "." + j);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] encoded1 = oid1.getEncoded();
					byte[] encoded1 = oid1.getEncoded();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid2 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(encoded1);
					ASN1ObjectIdentifier oid2 = ASN1ObjectIdentifier.getInstance(encoded1);
					if (oid1 == oid2)
					{
						fail("Shouldn't be the same: " + oid1 + " " + oid2);
					}
					if (!oid1.Equals(oid2))
					{
						fail("Should be equal: " + oid1 + " " + oid2);
					}
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid3 = oid2.intern();
					ASN1ObjectIdentifier oid3 = oid2.intern();
					if (oid2 != oid3)
					{
						fail("Should be the same: " + oid2 + " " + oid3);
					}
					if (!oid2.Equals(oid3))
					{
						fail("Should be equal: " + oid2 + " " + oid3);
					}
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] encoded2 = oid3.getEncoded();
					byte[] encoded2 = oid3.getEncoded();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid4 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(encoded2);
					ASN1ObjectIdentifier oid4 = ASN1ObjectIdentifier.getInstance(encoded2);
					if (oid3 != oid4)
					{
						fail("Should be taken from cache: " + oid3 + " " + oid4);
					}
					if (!oid3.Equals(oid4))
					{
						fail("Should be equal: " + oid3 + " " + oid4);
					}
				}
			}

			// make sure we're not leaking memory
			for (int i = 0; i < 100; i++)
			{
				for (int j = 0; j < 100; j++)
				{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid1 = new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.1.2." + i + "." + j);
					ASN1ObjectIdentifier oid1 = new ASN1ObjectIdentifier("1.1.2." + i + "." + j);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] encoded1 = oid1.getEncoded();
					byte[] encoded1 = oid1.getEncoded();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid2 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(encoded1);
					ASN1ObjectIdentifier oid2 = ASN1ObjectIdentifier.getInstance(encoded1);
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.asn1.ASN1ObjectIdentifier oid3 = org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(encoded1);
					ASN1ObjectIdentifier oid3 = ASN1ObjectIdentifier.getInstance(encoded1);
					if (oid1 == oid2)
					{
						fail("Shouldn't be the same: " + oid1 + " " + oid2);
					}
					if (oid2 == oid3)
					{
						fail("Shouldn't be the same: " + oid2 + " " + oid3);
					}
				}
			}
		}

		public static void Main(string[] args)
		{
			ObjectIdentifierTest test = new ObjectIdentifierTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result);
		}
	}

}