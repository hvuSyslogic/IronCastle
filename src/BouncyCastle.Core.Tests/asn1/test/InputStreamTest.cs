namespace org.bouncycastle.asn1.test
{

	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class InputStreamTest : SimpleTest
	{
		private static readonly byte[] outOfBoundsLength = new byte[] {(byte)0x30, unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff)};
		private static readonly byte[] negativeLength = new byte[] {(byte)0x30, unchecked((byte)0x84), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff), unchecked((byte)0xff)};
		private static readonly byte[] outsideLimitLength = new byte[] {(byte)0x30, unchecked((byte)0x83), (byte)0x0f, unchecked((byte)0xff), unchecked((byte)0xff)};


		public override string getName()
		{
			return "InputStream";
		}

		public override void performTest()
		{
			ASN1InputStream aIn = new ASN1InputStream(outOfBoundsLength);

			try
			{
				aIn.readObject();
				fail("out of bounds length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.StartsWith("DER length more than 4 bytes"))
				{
					fail("wrong exception: " + e.Message);
				}
			}

			aIn = new ASN1InputStream(negativeLength);

			try
			{
				aIn.readObject();
				fail("negative length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.Equals("corrupted stream - negative length found"))
				{
					fail("wrong exception: " + e.Message);
				}
			}

			aIn = new ASN1InputStream(outsideLimitLength);

			try
			{
				aIn.readObject();
				fail("outside limit length not detected.");
			}
			catch (IOException e)
			{
				if (!e.Message.Equals("corrupted stream - out of bounds length found"))
				{
					fail("wrong exception: " + e.Message);
				}
			}
		}

		public static void Main(string[] args)
		{
			runTest(new InputStreamTest());
		}
	}

}