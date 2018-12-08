using System;

namespace org.bouncycastle.asn1.test
{
	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using BodyPartList = org.bouncycastle.asn1.cmc.BodyPartList;
	using BodyPartPath = org.bouncycastle.asn1.cmc.BodyPartPath;
	using ModCertTemplate = org.bouncycastle.asn1.cmc.ModCertTemplate;
	using CertTemplate = org.bouncycastle.asn1.crmf.CertTemplate;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class ModCertTemplateTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new ModCertTemplateTest());
		}

		public override string getName()
		{
			return "ModCertTemplateTest";
		}

		public override void performTest()
		{

			BodyPartPath pkiDataReference = new BodyPartPath(new BodyPartID(10L));
			BodyPartList certReferences = new BodyPartList(new BodyPartID(12L));
			bool replace = false;
			CertTemplate certTemplate = CertTemplate.getInstance(new DLSequence(new DERTaggedObject(false, 1, new ASN1Integer(34L))));
			{
				ModCertTemplate modCertTemplate = new ModCertTemplate(pkiDataReference, certReferences, replace, certTemplate);

				byte[] b = modCertTemplate.getEncoded();

				ModCertTemplate modCertTemplateResult = ModCertTemplate.getInstance(b);

				isEquals("pkiDataReference", modCertTemplate.getPkiDataReference(), modCertTemplateResult.getPkiDataReference());
				isEquals("certReference", modCertTemplate.getCertReferences(), modCertTemplateResult.getCertReferences());
				isEquals("replacingFields", modCertTemplate.isReplacingFields(), modCertTemplateResult.isReplacingFields());
				isEquals("certTemplate", modCertTemplate.getCertTemplate().getSerialNumber(), modCertTemplateResult.getCertTemplate().getSerialNumber());
			}


			{
				// Test default 'result'
				ModCertTemplate mct = ModCertTemplate.getInstance(new DERSequence(new ASN1Encodable[]{pkiDataReference, certReferences, certTemplate}));

				isEquals("pkiDataReference", mct.getPkiDataReference(), pkiDataReference);
				isEquals("certReference", mct.getCertReferences(), certReferences);
				isEquals("DEFAULT TRUE on replacingFields", mct.isReplacingFields(), true);
				isEquals("certTemplate", mct.getCertTemplate().getSerialNumber(), certTemplate.getSerialNumber());
			}


			try
			{
				ModCertTemplate.getInstance(new DERSequence());
				fail("Sequence must be 3 or 4.");
			}
			catch (Exception t)
			{
				isEquals(t.GetType(), typeof(IllegalArgumentException));
			}


		}
	}

}