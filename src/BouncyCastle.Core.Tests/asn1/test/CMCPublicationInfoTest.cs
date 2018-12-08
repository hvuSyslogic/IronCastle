using System;

namespace org.bouncycastle.asn1.test
{

	using CMCPublicationInfo = org.bouncycastle.asn1.cmc.CMCPublicationInfo;
	using PKIPublicationInfo = org.bouncycastle.asn1.crmf.PKIPublicationInfo;
	using SinglePubInfo = org.bouncycastle.asn1.crmf.SinglePubInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class CMCPublicationInfoTest : SimpleTest
	{

		public override void performTest()
		{
			SecureRandom secureRandom = new SecureRandom();

			//
			// Test encode and decode.
			//

			// Not a real AlgorithmIdentifier
			AlgorithmIdentifier testIA = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.1.2.3"), DERNull.INSTANCE);
//JAVA TO C# CONVERTER NOTE: The following call to the 'RectangularArrays' helper class reproduces the rectangular array initialization that is automatic in Java:
//ORIGINAL LINE: byte[][] hashes = new byte[5][64];
			byte[][] hashes = RectangularArrays.ReturnRectangularSbyteArray(5, 64);
			for (int i = 0; i < hashes.Length; i++)
			{
				secureRandom.nextBytes(hashes[i]);
			}

			PKIPublicationInfo pinfo = new PKIPublicationInfo(new SinglePubInfo(SinglePubInfo.dontCare, null));

			CMCPublicationInfo cmcPublicationInfo = new CMCPublicationInfo(testIA,hashes,pinfo);
			byte[] b = cmcPublicationInfo.getEncoded();
			CMCPublicationInfo resCmcPublicationInfo = CMCPublicationInfo.getInstance(b);

			isEquals(resCmcPublicationInfo,cmcPublicationInfo);

			//
			// Test fail on small sequence.
			//

			try
			{
				CMCPublicationInfo.getInstance(new DERSequence(new ASN1Encodable[]{testIA}));
				fail("Expecting exception.");
			}
			catch (Exception t)
			{
				isEquals("Wrong exception: " + t.Message, t.GetType(), typeof(IllegalArgumentException));
			}

		}

		public override string getName()
		{
			return "CMCPublicationInfo";
		}

		public static void Main(string[] args)
		{
			runTest(new CMCPublicationInfoTest());
		}

	}

}