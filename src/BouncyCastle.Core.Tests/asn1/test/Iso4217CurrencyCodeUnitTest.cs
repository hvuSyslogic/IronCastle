namespace org.bouncycastle.asn1.test
{
	using Iso4217CurrencyCode = org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class Iso4217CurrencyCodeUnitTest : SimpleTest
	{
		private const string ALPHABETIC_CURRENCY_CODE = "AUD";
		private const int NUMERIC_CURRENCY_CODE = 1;

		public override string getName()
		{
			return "Iso4217CurrencyCode";
		}

		public override void performTest()
		{
			//
			// alphabetic
			//
			Iso4217CurrencyCode cc = new Iso4217CurrencyCode(ALPHABETIC_CURRENCY_CODE);

			checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);

			cc = Iso4217CurrencyCode.getInstance(cc);

			checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);

			ASN1Primitive obj = cc.toASN1Primitive();

			cc = Iso4217CurrencyCode.getInstance(obj);

			checkNumeric(cc, ALPHABETIC_CURRENCY_CODE);

			//
			// numeric
			//
			cc = new Iso4217CurrencyCode(NUMERIC_CURRENCY_CODE);

			checkNumeric(cc, NUMERIC_CURRENCY_CODE);

			cc = Iso4217CurrencyCode.getInstance(cc);

			checkNumeric(cc, NUMERIC_CURRENCY_CODE);

			obj = cc.toASN1Primitive();

			cc = Iso4217CurrencyCode.getInstance(obj);

			checkNumeric(cc, NUMERIC_CURRENCY_CODE);

			cc = Iso4217CurrencyCode.getInstance(null);

			if (cc != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				Iso4217CurrencyCode.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				new Iso4217CurrencyCode("ABCD");

				fail("constructor failed to detect out of range currencycode.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				new Iso4217CurrencyCode(0);

				fail("constructor failed to detect out of range small numeric code.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				new Iso4217CurrencyCode(1000);

				fail("constructor failed to detect out of range large numeric code.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkNumeric(Iso4217CurrencyCode cc, string code)
		{
			if (!cc.isAlphabetic())
			{
				fail("non-alphabetic code found when one expected.");
			}

			if (!cc.getAlphabetic().Equals(code))
			{
				fail("string codes don't match.");
			}
		}

		private void checkNumeric(Iso4217CurrencyCode cc, int code)
		{
			if (cc.isAlphabetic())
			{
				fail("alphabetic code found when one not expected.");
			}

			if (cc.getNumeric() != code)
			{
				fail("numeric codes don't match.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new Iso4217CurrencyCodeUnitTest());
		}
	}

}