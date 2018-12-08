using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.asn1.test
{

	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BiometricData = org.bouncycastle.asn1.x509.qualified.BiometricData;
	using TypeOfBiometricData = org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class BiometricDataUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "BiometricData";
		}

		private byte[] generateHash()
		{
			SecureRandom rand = new SecureRandom();
			byte[] bytes = new byte[20];

			rand.nextBytes(bytes);

			return bytes;
		}

		public override void performTest()
		{
			TypeOfBiometricData dataType = new TypeOfBiometricData(TypeOfBiometricData.HANDWRITTEN_SIGNATURE);
			AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
			ASN1OctetString dataHash = new DEROctetString(generateHash());
			BiometricData bd = new BiometricData(dataType, hashAlgorithm, dataHash);

			checkConstruction(bd, dataType, hashAlgorithm, dataHash, null);

			DERIA5String dataUri = new DERIA5String("http://test");

			bd = new BiometricData(dataType, hashAlgorithm, dataHash, dataUri);

			checkConstruction(bd, dataType, hashAlgorithm, dataHash, dataUri);

			bd = BiometricData.getInstance(null);

			if (bd != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				BiometricData.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(BiometricData bd, TypeOfBiometricData dataType, AlgorithmIdentifier hashAlgorithm, ASN1OctetString dataHash, DERIA5String dataUri)
		{
			checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);

			bd = BiometricData.getInstance(bd);

			checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);

			ASN1InputStream aIn = new ASN1InputStream(bd.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			bd = BiometricData.getInstance(seq);

			checkValues(bd, dataType, hashAlgorithm, dataHash, dataUri);
		}

		private void checkValues(BiometricData bd, TypeOfBiometricData dataType, AlgorithmIdentifier algID, ASN1OctetString dataHash, DERIA5String sourceDataURI)
		{
			if (!bd.getTypeOfBiometricData().Equals(dataType))
			{
				fail("types don't match.");
			}

			if (!bd.getHashAlgorithm().Equals(algID))
			{
				fail("hash algorithms don't match.");
			}

			if (!bd.getBiometricDataHash().Equals(dataHash))
			{
				fail("hash algorithms don't match.");
			}

			if (sourceDataURI != null)
			{
				if (!bd.getSourceDataUri().Equals(sourceDataURI))
				{
					fail("data uris don't match.");
				}
			}
			else if (bd.getSourceDataUri() != null)
			{
				fail("data uri found when none expected.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new BiometricDataUnitTest());
		}
	}

}