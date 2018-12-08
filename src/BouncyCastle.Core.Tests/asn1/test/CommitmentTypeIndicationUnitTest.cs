using org.bouncycastle.asn1.esf;

namespace org.bouncycastle.asn1.test
{

	using CommitmentTypeIdentifier = org.bouncycastle.asn1.esf.CommitmentTypeIdentifier;
	using CommitmentTypeIndication = org.bouncycastle.asn1.esf.CommitmentTypeIndication;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CommitmentTypeIndicationUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "CommitmentTypeIndication";
		}

		public override void performTest()
		{
			CommitmentTypeIndication cti = new CommitmentTypeIndication(CommitmentTypeIdentifier_Fields.proofOfOrigin);

			checkConstruction(cti, CommitmentTypeIdentifier_Fields.proofOfOrigin, null);

			ASN1Sequence qualifier = new DERSequence(new ASN1ObjectIdentifier("1.2"));

			cti = new CommitmentTypeIndication(CommitmentTypeIdentifier_Fields.proofOfOrigin, qualifier);

			checkConstruction(cti, CommitmentTypeIdentifier_Fields.proofOfOrigin, qualifier);

			cti = CommitmentTypeIndication.getInstance(null);

			if (cti != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				CommitmentTypeIndication.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(CommitmentTypeIndication mv, ASN1ObjectIdentifier commitmenttTypeId, ASN1Encodable qualifier)
		{
			checkStatement(mv, commitmenttTypeId, qualifier);

			mv = CommitmentTypeIndication.getInstance(mv);

			checkStatement(mv, commitmenttTypeId, qualifier);

			ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			mv = CommitmentTypeIndication.getInstance(seq);

			checkStatement(mv, commitmenttTypeId, qualifier);
		}

		private void checkStatement(CommitmentTypeIndication cti, ASN1ObjectIdentifier commitmentTypeId, ASN1Encodable qualifier)
		{
			if (!cti.getCommitmentTypeId().Equals(commitmentTypeId))
			{
				fail("commitmentTypeIds don't match.");
			}

			if (qualifier != null)
			{
				if (!cti.getCommitmentTypeQualifier().Equals(qualifier))
				{
					fail("qualifiers don't match.");
				}
			}
			else if (cti.getCommitmentTypeQualifier() != null)
			{
				fail("qualifier found when none expected.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new CommitmentTypeIndicationUnitTest());
		}
	}

}