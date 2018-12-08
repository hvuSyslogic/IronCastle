namespace org.bouncycastle.jce.provider.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// This test needs to be run with -Djava.security.debug=provider
	/// </summary>
	public class DRBGTest : SimpleTest
	{
		public DRBGTest()
		{
		}

		public override string getName()
		{
			return "DRBG";
		}

		public override void performTest()
		{
			Security.addProvider(new BouncyCastleProvider());

			SecureRandom.getInstance("DEFAULT", "BC");
		}

		public static void Main(string[] args)
		{
			runTest(new DRBGTest());
		}
	}

}