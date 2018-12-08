namespace org.bouncycastle.asn1.test
{
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PrivateKeyInfoTest : SimpleTest
	{
		private static readonly byte[] priv = Base64.decode("MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

		private static readonly byte[] privWithPub = Base64.decode("MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" + "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" + "Z9w7lshQhqowtrbLDFw4rXAxZuE=");


		public override string getName()
		{
			return "PrivateKeyInfoTest";
		}

		public override void performTest()
		{
			PrivateKeyInfo privInfo1 = PrivateKeyInfo.getInstance(priv);

			isTrue(!privInfo1.hasPublicKey());

			PrivateKeyInfo privInfo2 = new PrivateKeyInfo(privInfo1.getPrivateKeyAlgorithm(), privInfo1.parsePrivateKey());

			isTrue("enc 1 failed", areEqual(priv, privInfo2.getEncoded()));

			privInfo1 = PrivateKeyInfo.getInstance(privWithPub);

			isTrue(privInfo1.hasPublicKey());

			privInfo2 = new PrivateKeyInfo(privInfo1.getPrivateKeyAlgorithm(), privInfo1.parsePrivateKey(), privInfo1.getAttributes(), privInfo1.getPublicKeyData().getOctets());

			isTrue("enc 2 failed", areEqual(privWithPub, privInfo2.getEncoded()));
		}

		public static void Main(string[] args)
		{
			runTest(new PrivateKeyInfoTest());
		}
	}

}