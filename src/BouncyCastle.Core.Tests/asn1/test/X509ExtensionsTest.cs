namespace org.bouncycastle.asn1.test
{
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using X509ExtensionsGenerator = org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class X509ExtensionsTest : SimpleTest
	{
		private static readonly ASN1ObjectIdentifier OID_2 = new ASN1ObjectIdentifier("1.2.2");
		private static readonly ASN1ObjectIdentifier OID_3 = new ASN1ObjectIdentifier("1.2.3");
		private static readonly ASN1ObjectIdentifier OID_1 = new ASN1ObjectIdentifier("1.2.1");

		public override string getName()
		{
			return "X509Extensions";
		}

		public override void performTest()
		{
			X509ExtensionsGenerator gen = new X509ExtensionsGenerator();

			gen.addExtension(OID_1, true, new byte[20]);
			gen.addExtension(OID_2, true, new byte[20]);

			X509Extensions ext1 = gen.generate();
			X509Extensions ext2 = gen.generate();

			if (!ext1.Equals(ext2))
			{
				fail("equals test failed");
			}

			gen.reset();

			gen.addExtension(OID_2, true, new byte[20]);
			gen.addExtension(OID_1, true, new byte[20]);

			ext2 = gen.generate();

			if (ext1.Equals(ext2))
			{
				fail("inequality test failed");
			}

			if (!ext1.equivalent(ext2))
			{
				fail("equivalence true failed");
			}

			gen.reset();

			gen.addExtension(OID_1, true, new byte[22]);
			gen.addExtension(OID_2, true, new byte[20]);

			ext2 = gen.generate();

			if (ext1.Equals(ext2))
			{
				fail("inequality 1 failed");
			}

			if (ext1.equivalent(ext2))
			{
				fail("non-equivalence 1 failed");
			}

			gen.reset();

			gen.addExtension(OID_3, true, new byte[20]);
			gen.addExtension(OID_2, true, new byte[20]);

			ext2 = gen.generate();

			if (ext1.Equals(ext2))
			{
				fail("inequality 2 failed");
			}

			if (ext1.equivalent(ext2))
			{
				fail("non-equivalence 2 failed");
			}

			try
			{
				gen.addExtension(OID_2, true, new byte[20]);
				fail("repeated oid");
			}
			catch (IllegalArgumentException e)
			{
				if (!e.getMessage().Equals("extension 1.2.2 already added"))
				{
					fail("wrong exception on repeated oid: " + e.getMessage());
				}
			}
		}

		public static void Main(string[] args)
		{
			runTest(new X509ExtensionsTest());
		}
	}

}