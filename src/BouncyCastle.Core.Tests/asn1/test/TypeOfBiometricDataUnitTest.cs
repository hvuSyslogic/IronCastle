namespace org.bouncycastle.asn1.test
{

	using TypeOfBiometricData = org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class TypeOfBiometricDataUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "TypeOfBiometricData";
		}

		public override void performTest()
		{
			//
			// predefined
			//
			checkPredefinedType(TypeOfBiometricData.PICTURE);

			checkPredefinedType(TypeOfBiometricData.HANDWRITTEN_SIGNATURE);

			//
			// non-predefined
			//
			ASN1ObjectIdentifier localType = new ASN1ObjectIdentifier("1.1");

			TypeOfBiometricData type = new TypeOfBiometricData(localType);

			checkNonPredefined(type, localType);

			type = TypeOfBiometricData.getInstance(type);

			checkNonPredefined(type, localType);

			ASN1Primitive obj = type.toASN1Primitive();

			type = TypeOfBiometricData.getInstance(obj);

			checkNonPredefined(type, localType);

			type = TypeOfBiometricData.getInstance(null);

			if (type != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				TypeOfBiometricData.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			try
			{
				new TypeOfBiometricData(100);

				fail("constructor failed to detect bad predefined type.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}

			if (TypeOfBiometricData.PICTURE != 0)
			{
				fail("predefined picture should be 0");
			}

			if (TypeOfBiometricData.HANDWRITTEN_SIGNATURE != 1)
			{
				fail("predefined handwritten signature should be 1");
			}
		}

		private void checkPredefinedType(int predefinedType)
		{
			TypeOfBiometricData type = new TypeOfBiometricData(predefinedType);

			checkPredefined(type, predefinedType);

			type = TypeOfBiometricData.getInstance(type);

			checkPredefined(type, predefinedType);

			ASN1InputStream aIn = new ASN1InputStream(type.toASN1Primitive().getEncoded());

			ASN1Primitive obj = aIn.readObject();

			type = TypeOfBiometricData.getInstance(obj);

			checkPredefined(type, predefinedType);
		}

		private void checkPredefined(TypeOfBiometricData type, int value)
		{
			if (!type.isPredefined())
			{
				fail("predefined type expected but not found.");
			}

			if (type.getPredefinedBiometricType() != value)
			{
				fail("predefined type does not match.");
			}
		}

		private void checkNonPredefined(TypeOfBiometricData type, ASN1ObjectIdentifier value)
		{
			if (type.isPredefined())
			{
				fail("predefined type found when not expected.");
			}

			if (!type.getBiometricDataOid().Equals(value))
			{
				fail("data oid does not match.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new TypeOfBiometricDataUnitTest());
		}
	}

}