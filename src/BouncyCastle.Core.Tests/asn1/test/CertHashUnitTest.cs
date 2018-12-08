namespace org.bouncycastle.asn1.test
{

	using CertHash = org.bouncycastle.asn1.isismtt.ocsp.CertHash;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class CertHashUnitTest : ASN1UnitTest
	{
		public override string getName()
		{
			return "CertHash";
		}

		public override void performTest()
		{
			AlgorithmIdentifier algId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.2.3"));
			byte[] digest = new byte[20];

			CertHash certID = new CertHash(algId, digest);

			checkConstruction(certID, algId, digest);

			certID = CertHash.getInstance(null);

			if (certID != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				CertHash.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(CertHash certHash, AlgorithmIdentifier algId, byte[] digest)
		{
			checkValues(certHash, algId, digest);

			certHash = CertHash.getInstance(certHash);

			checkValues(certHash, algId, digest);

			ASN1InputStream aIn = new ASN1InputStream(certHash.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			certHash = CertHash.getInstance(seq);

			checkValues(certHash, algId, digest);
		}

		private void checkValues(CertHash certHash, AlgorithmIdentifier algId, byte[] digest)
		{
			checkMandatoryField("algorithmHash", algId, certHash.getHashAlgorithm());

			checkMandatoryField("certificateHash", digest, certHash.getCertificateHash());
		}

		public static void Main(string[] args)
		{
			runTest(new CertHashUnitTest());
		}
	}

}