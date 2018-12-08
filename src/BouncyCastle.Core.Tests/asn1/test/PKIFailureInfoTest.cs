using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.test
{

	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	/// <summary>
	/// PKIFailureInfoTest
	/// </summary>
	public class PKIFailureInfoTest : SimpleTest
	{
		// A correct hex encoded BAD_DATA_FORMAT PKIFailureInfo 
		private static readonly byte[] CORRECT_FAILURE_INFO = Base64.decode("AwIANQ==");

		public override string getName()
		{
			return "PKIFailureInfo";
		}

		private void testEncoding()
		{
			DERBitString bitString = (DERBitString)(new ASN1InputStream(CORRECT_FAILURE_INFO)).readObject();
			PKIFailureInfo correct = new PKIFailureInfo(bitString);

			PKIFailureInfo bug = new PKIFailureInfo(PKIFailureInfo.badRequest | PKIFailureInfo.badTime | PKIFailureInfo.badDataFormat | PKIFailureInfo.incorrectData);

			if (!areEqual(correct.getEncoded(ASN1Encoding_Fields.DER),bug.getEncoded(ASN1Encoding_Fields.DER)))
			{
				fail("encoding doesn't match");
			}
		}

		public override void performTest()
		{
			BitStringConstantTester.testFlagValueCorrect(0, PKIFailureInfo.badAlg);
			BitStringConstantTester.testFlagValueCorrect(1, PKIFailureInfo.badMessageCheck);
			BitStringConstantTester.testFlagValueCorrect(2, PKIFailureInfo.badRequest);
			BitStringConstantTester.testFlagValueCorrect(3, PKIFailureInfo.badTime);
			BitStringConstantTester.testFlagValueCorrect(4, PKIFailureInfo.badCertId);
			BitStringConstantTester.testFlagValueCorrect(5, PKIFailureInfo.badDataFormat);
			BitStringConstantTester.testFlagValueCorrect(6, PKIFailureInfo.wrongAuthority);
			BitStringConstantTester.testFlagValueCorrect(7, PKIFailureInfo.incorrectData);
			BitStringConstantTester.testFlagValueCorrect(8, PKIFailureInfo.missingTimeStamp);
			BitStringConstantTester.testFlagValueCorrect(9, PKIFailureInfo.badPOP);
			BitStringConstantTester.testFlagValueCorrect(10, PKIFailureInfo.certRevoked);
			BitStringConstantTester.testFlagValueCorrect(11, PKIFailureInfo.certConfirmed);
			BitStringConstantTester.testFlagValueCorrect(12, PKIFailureInfo.wrongIntegrity);
			BitStringConstantTester.testFlagValueCorrect(13, PKIFailureInfo.badRecipientNonce);
			BitStringConstantTester.testFlagValueCorrect(14, PKIFailureInfo.timeNotAvailable);
			BitStringConstantTester.testFlagValueCorrect(15, PKIFailureInfo.unacceptedPolicy);
			BitStringConstantTester.testFlagValueCorrect(16, PKIFailureInfo.unacceptedExtension);
			BitStringConstantTester.testFlagValueCorrect(17, PKIFailureInfo.addInfoNotAvailable);
			BitStringConstantTester.testFlagValueCorrect(18, PKIFailureInfo.badSenderNonce);
			BitStringConstantTester.testFlagValueCorrect(19, PKIFailureInfo.badCertTemplate);
			BitStringConstantTester.testFlagValueCorrect(20, PKIFailureInfo.signerNotTrusted);
			BitStringConstantTester.testFlagValueCorrect(21, PKIFailureInfo.transactionIdInUse);
			BitStringConstantTester.testFlagValueCorrect(22, PKIFailureInfo.unsupportedVersion);
			BitStringConstantTester.testFlagValueCorrect(23, PKIFailureInfo.notAuthorized);
			BitStringConstantTester.testFlagValueCorrect(24, PKIFailureInfo.systemUnavail);
			BitStringConstantTester.testFlagValueCorrect(25, PKIFailureInfo.systemFailure);
			BitStringConstantTester.testFlagValueCorrect(26, PKIFailureInfo.duplicateCertReq);

			testEncoding();
		}

		public static void Main(string[] args)
		{
			runTest(new PKIFailureInfoTest());
		}
	}

}