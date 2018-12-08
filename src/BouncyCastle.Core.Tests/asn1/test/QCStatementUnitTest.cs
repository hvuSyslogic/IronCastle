using org.bouncycastle.asn1.x509.qualified;

namespace org.bouncycastle.asn1.test
{

	using QCStatement = org.bouncycastle.asn1.x509.qualified.QCStatement;
	using RFC3739QCObjectIdentifiers = org.bouncycastle.asn1.x509.qualified.RFC3739QCObjectIdentifiers;
	using SemanticsInformation = org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class QCStatementUnitTest : SimpleTest
	{
		public override string getName()
		{
			return "QCStatement";
		}

		public override void performTest()
		{
			QCStatement mv = new QCStatement(RFC3739QCObjectIdentifiers_Fields.id_qcs_pkixQCSyntax_v1);

			checkConstruction(mv, RFC3739QCObjectIdentifiers_Fields.id_qcs_pkixQCSyntax_v1, null);

			ASN1Encodable info = new SemanticsInformation(new ASN1ObjectIdentifier("1.2"));

			mv = new QCStatement(RFC3739QCObjectIdentifiers_Fields.id_qcs_pkixQCSyntax_v1, info);

			checkConstruction(mv, RFC3739QCObjectIdentifiers_Fields.id_qcs_pkixQCSyntax_v1, info);

			mv = QCStatement.getInstance(null);

			if (mv != null)
			{
				fail("null getInstance() failed.");
			}

			try
			{
				QCStatement.getInstance(new object());

				fail("getInstance() failed to detect bad object.");
			}
			catch (IllegalArgumentException)
			{
				// expected
			}
		}

		private void checkConstruction(QCStatement mv, ASN1ObjectIdentifier statementId, ASN1Encodable statementInfo)
		{
			checkStatement(mv, statementId, statementInfo);

			mv = QCStatement.getInstance(mv);

			checkStatement(mv, statementId, statementInfo);

			ASN1InputStream aIn = new ASN1InputStream(mv.toASN1Primitive().getEncoded());

			ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

			mv = QCStatement.getInstance(seq);

			checkStatement(mv, statementId, statementInfo);
		}

		private void checkStatement(QCStatement qcs, ASN1ObjectIdentifier statementId, ASN1Encodable statementInfo)
		{
			if (!qcs.getStatementId().Equals(statementId))
			{
				fail("statementIds don't match.");
			}

			if (statementInfo != null)
			{
				if (!qcs.getStatementInfo().Equals(statementInfo))
				{
					fail("statementInfos don't match.");
				}
			}
			else if (qcs.getStatementInfo() != null)
			{
				fail("statementInfo found when none expected.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new QCStatementUnitTest());
		}
	}

}