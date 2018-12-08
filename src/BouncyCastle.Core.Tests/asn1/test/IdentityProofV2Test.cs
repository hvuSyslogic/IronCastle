using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{

	using IdentityProofV2 = org.bouncycastle.asn1.cmc.IdentityProofV2;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class IdentityProofV2Test : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new IdentityProofV2Test());
		}

		public override string getName()
		{
			return "IdentityProofV2";
		}

		public override void performTest()
		{
			IdentityProofV2 proofV2 = new IdentityProofV2(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.encryptionAlgorithm, new ASN1Integer(10L)), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.bagtypes, new ASN1Integer(10L)), "Cats".GetBytes());

			byte[] b = proofV2.getEncoded();
			IdentityProofV2 proofV2Res = IdentityProofV2.getInstance(b);

			isEquals("proofAldID", proofV2.getProofAlgID(), proofV2Res.getProofAlgID());
			isEquals("macAlgId", proofV2.getMacAlgId(), proofV2Res.getMacAlgId());
			isTrue("witness", areEqual(proofV2.getWitness(), proofV2Res.getWitness()));


			try
			{
				IdentityProofV2.getInstance(new DERSequence(new ASN1Encodable[0]));
				fail("Sequence must be length of 3");
			}
			catch (Exception t)
			{
				isEquals("Exception incorrect", t.GetType(), typeof(IllegalArgumentException));
			}
		}
	}

}