namespace org.bouncycastle.asn1.test
{

	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;
	using NameOrPseudonym = org.bouncycastle.asn1.x509.sigi.NameOrPseudonym;
	using PersonalData = org.bouncycastle.asn1.x509.sigi.PersonalData;

	public class PersonalDataUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "PersonalData";
		}

		public override void performTest()
		{
			NameOrPseudonym nameOrPseudonym = new NameOrPseudonym("pseudonym");
			BigInteger nameDistinguisher = BigInteger.valueOf(10);
			ASN1GeneralizedTime dateOfBirth = new ASN1GeneralizedTime("20070315173729Z");
			DirectoryString placeOfBirth = new DirectoryString("placeOfBirth");
			string gender = "M";
			DirectoryString postalAddress = new DirectoryString("address");

			PersonalData data = new PersonalData(nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);

			checkConstruction(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);

			data = new PersonalData(nameOrPseudonym, null, dateOfBirth, placeOfBirth, gender, postalAddress);

			checkConstruction(data, nameOrPseudonym, null, dateOfBirth, placeOfBirth, gender, postalAddress);

			data = new PersonalData(nameOrPseudonym, nameDistinguisher, null, placeOfBirth, gender, postalAddress);

			checkConstruction(data, nameOrPseudonym, nameDistinguisher, null, placeOfBirth, gender, postalAddress);

			data = new PersonalData(nameOrPseudonym, nameDistinguisher, dateOfBirth, null, gender, postalAddress);

			checkConstruction(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, null, gender, postalAddress);

			data = new PersonalData(nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, null, postalAddress);

			checkConstruction(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, null, postalAddress);

			data = new PersonalData(nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, null);

			checkConstruction(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, null);

			data = PersonalData.getInstance(null);

			if (data != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				PersonalData.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(PersonalData data, NameOrPseudonym nameOrPseudonym, BigInteger nameDistinguisher, ASN1GeneralizedTime dateOfBirth, DirectoryString placeOfBirth, string gender, DirectoryString postalAddress)
		{
			checkValues(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);

			data = PersonalData.getInstance(data);

			checkValues(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);

			ASN1InputStream aIn = new ASN1InputStream(data.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			data = PersonalData.getInstance(seq);

			checkValues(data, nameOrPseudonym, nameDistinguisher, dateOfBirth, placeOfBirth, gender, postalAddress);
		}

		private void checkValues(PersonalData data, NameOrPseudonym nameOrPseudonym, BigInteger nameDistinguisher, ASN1GeneralizedTime dateOfBirth, DirectoryString placeOfBirth, string gender, DirectoryString postalAddress)
		{
			checkMandatoryField("nameOrPseudonym", nameOrPseudonym, data.getNameOrPseudonym());
			checkOptionalField("nameDistinguisher", nameDistinguisher, data.getNameDistinguisher());
			checkOptionalField("dateOfBirth", dateOfBirth, data.getDateOfBirth());
			checkOptionalField("placeOfBirth", placeOfBirth, data.getPlaceOfBirth());
			checkOptionalField("gender", gender, data.getGender());
			checkOptionalField("postalAddress", postalAddress, data.getPostalAddress());
		}

		public static void Main(string[] args)
		{
			runTest(new PersonalDataUnitTest());
		}
	}

}