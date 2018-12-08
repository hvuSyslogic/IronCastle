namespace org.bouncycastle.openpgp.test
{

	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class PGPParsingTest : SimpleTest
	{
		public override void performTest()
		{
			PGPPublicKeyRingCollection pubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(this.GetType().getResourceAsStream("bigpub.asc")), new JcaKeyFingerprintCalculator());
		}

		public override string getName()
		{
			return "PGPParsingTest";
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new PGPParsingTest());
		}
	}

}