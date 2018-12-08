namespace org.bouncycastle.asn1.test
{

	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class SubjectKeyIdentifierTest : SimpleTest
	{
		private static byte[] pubKeyInfo = Base64.decode("MFgwCwYJKoZIhvcNAQEBA0kAMEYCQQC6wMMmHYMZszT/7bNFMn+gaZoiWJLVP8ODRuu1C2jeAe" + "QpxM+5Oe7PaN2GNy3nBE4EOYkB5pMJWA0y9n04FX8NAgED");

		private static byte[] shaID = Hex.decode("d8128a06d6c2feb0865994a2936e7b75b836a021");
		private static byte[] shaTruncID = Hex.decode("436e7b75b836a021");

		public override string getName()
		{
			return "SubjectKeyIdentifier";
		}

		public override void performTest()
		{
	//        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pubKeyInfo));
	//        SubjectKeyIdentifier ski = SubjectKeyIdentifier.createSHA1KeyIdentifier(pubInfo);
	//
	//        if (!Arrays.areEqual(shaID, ski.getKeyIdentifier()))
	//        {
	//            fail("SHA-1 ID does not match");
	//        }
	//
	//        ski = SubjectKeyIdentifier.createTruncatedSHA1KeyIdentifier(pubInfo);
	//
	//        if (!Arrays.areEqual(shaTruncID, ski.getKeyIdentifier()))
	//        {
	//            fail("truncated SHA-1 ID does not match");
	//        }
		}

		public static void Main(string[] args)
		{
			runTest(new SubjectKeyIdentifierTest());
		}
	}

}