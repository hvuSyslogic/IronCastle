namespace org.bouncycastle.asn1.test
{


	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using DhSigStatic = org.bouncycastle.asn1.crmf.DhSigStatic;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DhSigStaticTest : SimpleTest
	{


		public override void performTest()
		{
			// Test correct encode / decode

			// Test encode and decode from Long and from other instance of DhSigStatic
			DhSigStatic dhS = new DhSigStatic(new byte[20]);
			instanceTest(dhS);

			dhS = new DhSigStatic(new IssuerAndSerialNumber(new X500Name("CN=Test"), BigInteger.valueOf(20)), new byte[20]);
			instanceTest(dhS);

			dhS = DhSigStatic.getInstance(new DERSequence(new DEROctetString(Hex.decode("0102030405060708090a"))));

			isTrue(Arrays.areEqual(Hex.decode("0102030405060708090a"), dhS.getHashValue()));

			try
			{
				dhS = DhSigStatic.getInstance(new DERSequence(new ASN1Encodable[]
				{
					new DEROctetString(Hex.decode("0102030405060708090a")),
					new DEROctetString(Hex.decode("0102030405060708090a")),
					new DEROctetString(Hex.decode("0102030405060708090a"))
				}));
				fail("no exception");
			}
			catch (IllegalArgumentException e)
			{
				isEquals(e.getMessage(), "sequence wrong length for DhSigStatic", e.getMessage());
			}
		}

		private void instanceTest(DhSigStatic bpd)
		{
			byte[] b = bpd.getEncoded();
			DhSigStatic resBpd = DhSigStatic.getInstance(b);
			isTrue("hash check failed", areEqual(bpd.getHashValue(), resBpd.getHashValue()));
			isEquals("issuerAndSerial failed", bpd.getIssuerAndSerial(), resBpd.getIssuerAndSerial());
		}

		public override string getName()
		{
			return "DhSigStaticTest";
		}

		public static void Main(string[] args)
		{
			runTest(new DhSigStaticTest());
		}
	}


}