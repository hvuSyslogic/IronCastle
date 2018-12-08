namespace org.bouncycastle.asn1.test
{

	using AdditionalInformationSyntax = org.bouncycastle.asn1.isismtt.x509.AdditionalInformationSyntax;
	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;

	public class AdditionalInformationSyntaxUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "AdditionalInformationSyntax";
		}

		public override void performTest()
		{
			AdditionalInformationSyntax syntax = new AdditionalInformationSyntax("hello world");

			checkConstruction(syntax, new DirectoryString("hello world"));

			try
			{
				AdditionalInformationSyntax.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(AdditionalInformationSyntax syntax, DirectoryString information)
		{
			checkValues(syntax, information);

			syntax = AdditionalInformationSyntax.getInstance(syntax);

			checkValues(syntax, information);

			ASN1InputStream aIn = new ASN1InputStream(syntax.toASN1Primitive().getEncoded());

			ASN1String info = (ASN1String)aIn.readObject();

			syntax = AdditionalInformationSyntax.getInstance(info);

			checkValues(syntax, information);
		}

		private void checkValues(AdditionalInformationSyntax syntax, DirectoryString information)
		{
			checkMandatoryField("information", information, syntax.getInformation());
		}

		public static void Main(string[] args)
		{
			runTest(new AdditionalInformationSyntaxUnitTest());
		}
	}

}