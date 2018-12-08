using org.bouncycastle.asn1.esf;

namespace org.bouncycastle.asn1.test
{

	using CommitmentTypeIdentifier = org.bouncycastle.asn1.esf.CommitmentTypeIdentifier;
	using CommitmentTypeQualifier = org.bouncycastle.asn1.esf.CommitmentTypeQualifier;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CommitmentTypeQualifierUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "CommitmentTypeQualifier";
		}

		public override void performTest()
		{
			CommitmentTypeQualifier ctq = new CommitmentTypeQualifier(CommitmentTypeIdentifier_Fields.proofOfOrigin);

			checkConstruction(ctq, CommitmentTypeIdentifier_Fields.proofOfOrigin, null);

			ASN1Encodable info = new ASN1ObjectIdentifier("1.2");

			ctq = new CommitmentTypeQualifier(CommitmentTypeIdentifier_Fields.proofOfOrigin, info);

			checkConstruction(ctq, CommitmentTypeIdentifier_Fields.proofOfOrigin, info);

			ctq = CommitmentTypeQualifier.getInstance(null);

			if (ctq != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				CommitmentTypeQualifier.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(CommitmentTypeQualifier mv, ASN1ObjectIdentifier commitmenttTypeId, ASN1Encodable qualifier)
		{
			checkStatement(mv, commitmenttTypeId, qualifier);

			mv = CommitmentTypeQualifier.getInstance(mv);

			checkStatement(mv, commitmenttTypeId, qualifier);

			ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			mv = CommitmentTypeQualifier.getInstance(seq);

			checkStatement(mv, commitmenttTypeId, qualifier);
		}

		private void checkStatement(CommitmentTypeQualifier ctq, ASN1ObjectIdentifier commitmentTypeId, ASN1Encodable qualifier)
		{
			if (!ctq.getCommitmentTypeIdentifier().Equals(commitmentTypeId))
			{
				fail("commitmentTypeIds don't match.");
			}

			if (qualifier != null)
			{
				if (!ctq.getQualifier().Equals(qualifier))
				{
					fail("qualifiers don't match.");
				}
			}
			else if (ctq.getQualifier() != null)
			{
				fail("qualifier found when none expected.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new CommitmentTypeQualifierUnitTest());
		}
	}

}