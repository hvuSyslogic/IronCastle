namespace org.bouncycastle.util.encoders.test
{


	public class HexTest : AbstractCoderTest
	{
		private const string invalid1 = "%O4T";
		private const string invalid2 = "FZI4";
		private const string invalid3 = "ae%E";
		private const string invalid4 = "fO4%";
		private const string invalid5 = "beefe";
		private const string invalid6 = "beefs";

		public HexTest(string name) : base(name)
		{
		}

		public override void setUp()
		{
			base.setUp();
			enc = new HexEncoder();
		}

		public override char paddingChar()
		{
			return (char)0;
		}

		public override bool isEncodedChar(char c)
		{
			if ('A' <= c && c <= 'F')
			{
				return true;
			}
			if ('a' <= c && c <= 'f')
			{
				return true;
			}
			if ('0' <= c && c <= '9')
			{
				return true;
			}
			return false;
		}

		public virtual void testInvalidInput()
		{
			string[] invalid = new string[] {invalid1, invalid2, invalid3, invalid4, invalid5, invalid6};

			for (int i = 0; i != invalid.Length; i++)
			{
				invalidTest(invalid[i]);
				invalidTest(Strings.toByteArray(invalid[i]));
			}
		}

		private void invalidTest(string data)
		{
			try
			{
				Hex.decode(data);
			}
			catch (DecoderException)
			{
				return;
			}

			fail("invalid String data parsed");
		}

		private void invalidTest(byte[] data)
		{
			try
			{
				Hex.decode(data);
			}
			catch (DecoderException)
			{
				return;
			}

			fail("invalid byte data parsed");
		}
	}

}