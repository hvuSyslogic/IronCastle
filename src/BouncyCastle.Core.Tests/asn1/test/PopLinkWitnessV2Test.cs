using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{
	using PopLinkWitnessV2 = org.bouncycastle.asn1.cmc.PopLinkWitnessV2;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class PopLinkWitnessV2Test : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new PopLinkWitnessV2Test());
		}

		public override string getName()
		{
			return "PopLinkWitnessV2Test";
		}

		public override void performTest()
		{
			// Object identifiers real but not correct in this context.
			PopLinkWitnessV2 popLinkWitnessV2 = new PopLinkWitnessV2(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.bagtypes, new ASN1Integer(10L)), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.crlTypes, new ASN1Integer(12L)), "cats".GetBytes());

			byte[] b = popLinkWitnessV2.getEncoded();
			PopLinkWitnessV2 popLinkWitnessV2Result = PopLinkWitnessV2.getInstance(b);

			isEquals(popLinkWitnessV2, popLinkWitnessV2Result);

			try
			{
				PopLinkWitnessV2.getInstance(new DERSequence());
				fail("Length must be 3");
			}
			catch (Exception t)
			{
				isEquals(t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}