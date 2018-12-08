using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{

	using PublishTrustAnchors = org.bouncycastle.asn1.cmc.PublishTrustAnchors;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PublishTrustAnchorsTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PublishTrustAnchorsTest());
		}

		public override string getName()
		{
			return "PublishTrustAnchorsTest";
		}

		public override void performTest()
		{
			PublishTrustAnchors publishTrustAnchors = new PublishTrustAnchors(new BigInteger("10"), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.crlTypes, new ASN1Integer(5L)), new byte[][]{"cats".GetBytes()});

			byte[] b = publishTrustAnchors.getEncoded();

			PublishTrustAnchors publishTrustAnchorsResult = PublishTrustAnchors.getInstance(b);

			isEquals("seqNumber", publishTrustAnchors.getSeqNumber(), publishTrustAnchorsResult.getSeqNumber());
			isEquals("hashAlgorithm", publishTrustAnchors.getHashAlgorithm(), publishTrustAnchorsResult.getHashAlgorithm());
			isTrue("anchorHashes", areEqual(publishTrustAnchors.getAnchorHashes(), publishTrustAnchorsResult.getAnchorHashes()));

			try
			{
				PublishTrustAnchors.getInstance(new DERSequence());
				fail("Sequence must be 3");
			}
			catch (Exception t)
			{
				isEquals("Expect IllegalArgumentException", t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}