namespace org.bouncycastle.asn1.test
{

	using CAST5CBCParameters = org.bouncycastle.asn1.misc.CAST5CBCParameters;
	using IDEACBCPar = org.bouncycastle.asn1.misc.IDEACBCPar;
	using NetscapeCertType = org.bouncycastle.asn1.misc.NetscapeCertType;
	using NetscapeRevocationURL = org.bouncycastle.asn1.misc.NetscapeRevocationURL;
	using VerisignCzagExtension = org.bouncycastle.asn1.misc.VerisignCzagExtension;
	using Arrays = org.bouncycastle.util.Arrays;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class MiscTest : SimpleTest
	{
		public virtual void shouldFailOnExtraData()
		{
			// basic construction
			DERBitString s1 = new DERBitString(new byte[0], 0);

			ASN1Primitive.fromByteArray(s1.getEncoded());

			ASN1Primitive.fromByteArray((new BERSequence(s1)).getEncoded());

			try
			{
				ASN1Primitive obj = ASN1Primitive.fromByteArray(Arrays.concatenate(s1.getEncoded(), new byte[1]));
				fail("no exception");
			}
			catch (IOException e)
			{
				if (!"Extra data detected in stream".Equals(e.Message))
				{
					fail("wrong exception");
				}
			}
		}

		public virtual void derIntegerTest()
		{
			try
			{
				new ASN1Integer(new byte[] {0, 0, 0, 1});
			}
			catch (IllegalArgumentException e)
			{
				isTrue("wrong exc", "malformed integer".Equals(e.getMessage()));
			}

			try
			{
				new ASN1Integer(new byte[] {unchecked((byte)0xff), unchecked((byte)0x80), 0, 1});
			}
			catch (IllegalArgumentException e)
			{
				isTrue("wrong exc", "malformed integer".Equals(e.getMessage()));
			}

			try
			{
				new ASN1Enumerated(new byte[] {0, 0, 0, 1});
			}
			catch (IllegalArgumentException e)
			{
				isTrue("wrong exc", "malformed enumerated".Equals(e.getMessage()));
			}

			try
			{
				new ASN1Enumerated(new byte[] {unchecked((byte)0xff), unchecked((byte)0x80), 0, 1});
			}
			catch (IllegalArgumentException e)
			{
				isTrue("wrong exc", "malformed enumerated".Equals(e.getMessage()));
			}
		}

		public override void performTest()
		{
			byte[] testIv = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};

			ASN1Encodable[] values = new ASN1Encodable[]
			{
				new CAST5CBCParameters(testIv, 128),
				new NetscapeCertType(NetscapeCertType.smime),
				new VerisignCzagExtension(new DERIA5String("hello")),
				new IDEACBCPar(testIv),
				new NetscapeRevocationURL(new DERIA5String("http://test"))
			};

			byte[] data = Base64.decode("MA4ECAECAwQFBgcIAgIAgAMCBSAWBWhlbGxvMAoECAECAwQFBgcIFgtodHRwOi8vdGVzdA==");

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			for (int i = 0; i != values.Length; i++)
			{
				aOut.writeObject(values[i]);
			}

			if (!areEqual(bOut.toByteArray(), data))
			{
				fail("Failed data check");
			}

			ASN1InputStream aIn = new ASN1InputStream(bOut.toByteArray());

			for (int i = 0; i != values.Length; i++)
			{
				ASN1Primitive o = aIn.readObject();
				if (!values[i].Equals(o))
				{
					fail("Failed equality test for " + o);
				}

				if (o.GetHashCode() != values[i].GetHashCode())
				{
					fail("Failed hashCode test for " + o);
				}
			}

			shouldFailOnExtraData();
			derIntegerTest();
		}

		public override string getName()
		{
			return "Misc";
		}

		public static void Main(string[] args)
		{
			runTest(new MiscTest());
		}
	}

}