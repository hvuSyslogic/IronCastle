namespace org.bouncycastle.asn1.test
{
	using Iso4217CurrencyCode = org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
	using MonetaryValue = org.bouncycastle.asn1.x509.qualified.MonetaryValue;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class MonetaryValueUnitTest : SimpleTest
	{
		private const int TEST_AMOUNT = 100;
		private const int ZERO_EXPONENT = 0;

		private const string CURRENCY_CODE = "AUD";

		public override string getName()
		{
			return "MonetaryValue";
		}

		public override void performTest()
		{
			MonetaryValue mv = new MonetaryValue(new Iso4217CurrencyCode(CURRENCY_CODE), TEST_AMOUNT, ZERO_EXPONENT);

			checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);

			mv = MonetaryValue.getInstance(mv);

			checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);

			ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			mv = MonetaryValue.getInstance(seq);

			checkValues(mv, TEST_AMOUNT, ZERO_EXPONENT);

			mv = MonetaryValue.getInstance(null);

			if (mv != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				MonetaryValue.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkValues(MonetaryValue mv, int amount, int exponent)
		{
			if (mv.getAmount().intValue() != amount)
			{
				fail("amounts don't match.");
			}

			if (mv.getExponent().intValue() != exponent)
			{
				fail("exponents don't match.");
			}

			Iso4217CurrencyCode cc = mv.getCurrency();

			if (!cc.getAlphabetic().Equals(CURRENCY_CODE))
			{
				fail("currency code wrong");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new MonetaryValueUnitTest());
		}
	}

}