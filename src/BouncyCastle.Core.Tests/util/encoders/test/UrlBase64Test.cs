namespace org.bouncycastle.util.encoders.test
{


	public class UrlBase64Test : AbstractCoderTest
	{
		private const string sample1 = "mO4TyLWG7vjFWdKT8IJcVbZ_jwc.";
		private static readonly byte[] sample1Bytes = Hex.decode("98ee13c8b586eef8c559d293f0825c55b67f8f07");
		private const string sample2 = "F4I4p8Vf_mS-Kxvri3FPoMcqmJ1f";
		private static readonly byte[] sample2Bytes = Hex.decode("178238a7c55ffe64be2b1beb8b714fa0c72a989d5f");
		private const string sample3 = "UJmEdJYodqHJmd7Rtv6_OP29_jUEFw..";
		private static readonly byte[] sample3Bytes = Hex.decode("50998474962876a1c999ded1b6febf38fdbdfe350417");

		private const string invalid1 = "%O4TyLWG7vjFWdKT8IJcVbZ_jwc.";
		private const string invalid2 = "F%I4p8Vf_mS-Kxvri3FPoMcqmJ1f";
		private const string invalid3 = "UJ%EdJYodqHJmd7Rtv6_OP29_jUEFw..";
		private const string invalid4 = "mO4%yLWG7vjFWdKT8IJcVbZ_jwc.";
		private const string invalid5 = "UJmEdJYodqHJmd7Rtv6_OP29_jUEF%..";
		private const string invalid6 = "mO4TyLWG7vjFWdKT8IJcVbZ_jw%.";
		private const string invalid7 = "F4I4p8Vf_mS-Kxvri3FPoMcqmJ1%";
		private const string invalid8 = "UJmEdJYodqHJmd7Rtv6_OP29_jUE%c..";
		private const string invalid9 = "mO4TyLWG7vjFWdKT8IJcVbZ_j%c.";
		private const string invalida = "F4I4p8Vf_mS-Kxvri3FPoMcqmJ%1";
		private const string invalidb = "UJmEdJYodqHJmd7Rtv6_OP29_jU%Fc..";
		private const string invalidc = "mO4TyLWG7vjFWdKT8IJcVbZ_%wc.";
		private const string invalidd = "F4I4p8Vf_mS-Kxvri3FPoMcqm%1c";
		private const string invalide = "UJmEdJYodqHJmd7Rtv6/OP29/jUEFw.1";
		private const string invalidg = "M";

		public UrlBase64Test(string name) : base(name)
		{
		}

		public override void setUp()
		{
			base.setUp();
			enc = new UrlBase64Encoder();
		}

		public virtual void testSamples()
		{
			assertTrue(Arrays.areEqual(new byte[0], UrlBase64.decode("")));
			assertEquals(0, UrlBase64.decode(new byte[0], new ByteArrayOutputStream()));
			assertTrue(Arrays.areEqual(sample1Bytes, UrlBase64.decode(sample1)));
			assertTrue(Arrays.areEqual(sample1Bytes, UrlBase64.decode(Strings.toByteArray(sample1))));
			assertTrue(Arrays.areEqual(sample2Bytes, UrlBase64.decode(sample2)));
			assertTrue(Arrays.areEqual(sample2Bytes, UrlBase64.decode(Strings.toByteArray(sample2))));
			assertTrue(Arrays.areEqual(sample3Bytes, UrlBase64.decode(sample3)));
			assertTrue(Arrays.areEqual(sample3Bytes, UrlBase64.decode(Strings.toByteArray(sample3))));
		}

		public virtual void testInvalidInput()
		{
			string[] invalid = new string[] {invalid1, invalid2, invalid3, invalid4, invalid5, invalid6, invalid7, invalid8, invalid9, invalida, invalidb, invalidc, invalidd, invalide, invalidg};

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
				UrlBase64.decode(data);
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
				UrlBase64.decode(data);
			}
			catch (DecoderException)
			{
				return;
			}

			fail("invalid byte data parsed");
		}

		public override char paddingChar()
		{
			return '.';
		}

		public override bool isEncodedChar(char c)
		{
			if (Character.isLetterOrDigit(c))
			{
				return true;
			}
			else if (c == '-')
			{
				return true;
			}
			else if (c == '_')
			{
				return true;
			}
			return false;
		}
	}

}