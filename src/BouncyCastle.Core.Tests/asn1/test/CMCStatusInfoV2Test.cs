using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{

	using BodyPartID = org.bouncycastle.asn1.cmc.BodyPartID;
	using CMCFailInfo = org.bouncycastle.asn1.cmc.CMCFailInfo;
	using CMCStatus = org.bouncycastle.asn1.cmc.CMCStatus;
	using CMCStatusInfoV2 = org.bouncycastle.asn1.cmc.CMCStatusInfoV2;
	using CMCStatusInfoV2Builder = org.bouncycastle.asn1.cmc.CMCStatusInfoV2Builder;
	using ExtendedFailInfo = org.bouncycastle.asn1.cmc.ExtendedFailInfo;
	using PendInfo = org.bouncycastle.asn1.cmc.PendInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Strings = org.bouncycastle.util.Strings;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class CMCStatusInfoV2Test : SimpleTest
	{

		public static void Main(string[] args)
		{
			runTest(new CMCStatusInfoV2Test());
		}

		public override string getName()
		{
			return "CMCStatusInfoV2Test";
		}

		public override void performTest()
		{
			{ // Without optional status String

				CMCStatusInfoV2Builder bldr = new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10));

				CMCStatusInfoV2 cmsInfo = bldr.build();

				isTrue("Has statusString", null == cmsInfo.getStatusString());
				isEquals("Has other info", false, cmsInfo.hasOtherInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

				// Same
				isEquals("CMCStatus with no optional part", cmsInfo, res);

				isEquals("Has other info", false, res.hasOtherInfo());

			}

			{ // Without optional other info.

				CMCStatusInfoV2Builder bldr = (new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats");

				CMCStatusInfoV2 cmsInfo = bldr.build();

				isEquals("Has other info", false, cmsInfo.hasOtherInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

				// Same
				isEquals("CMCStatus with no optional part", cmsInfo, res);

				isEquals("Has other info", false, res.hasOtherInfo());

			}


			{ // With optional info: PendInfo
				CMCStatusInfoV2Builder bldr = (new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats").setOtherInfo(new PendInfo(Strings.toByteArray("fish"), new DERGeneralizedTime(DateTime.Now)));

				CMCStatusInfoV2 cmsInfo = bldr.build();

				isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
				isEquals("Other is NOT fail info", false, cmsInfo.getOtherStatusInfo().isFailInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

				isEquals("With optional info: PendInfo", cmsInfo, res);

				isEquals("Must have other info", true, res.hasOtherInfo());
				isEquals("Other is NOT fail info", false, res.getOtherStatusInfo().isFailInfo());
			}


			{ // With optional info: CMCFailInfo
				CMCStatusInfoV2Builder bldr = (new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats").setOtherInfo(CMCFailInfo.authDataFail);

				CMCStatusInfoV2 cmsInfo = bldr.build();

				isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
				isEquals("Other is fail info", true, cmsInfo.getOtherStatusInfo().isFailInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

				isEquals("With optional info: CMCFailInfo", cmsInfo, res);

				isEquals("Must have other info", true, res.hasOtherInfo());
				isEquals("Other is fail info", true, res.getOtherStatusInfo().isFailInfo());
			}


			{ // With optional info: ExtendedFailInfo
				CMCStatusInfoV2Builder bldr = (new CMCStatusInfoV2Builder(CMCStatus.confirmRequired, new BodyPartID(10))).setStatusString("Cats").setOtherInfo(new ExtendedFailInfo(PKCSObjectIdentifiers_Fields.bagtypes, new DEROctetString("fish".GetBytes())));

				CMCStatusInfoV2 cmsInfo = bldr.build();

				isEquals("Must have other info", true, cmsInfo.hasOtherInfo());
				isEquals("Other is extended fail info", true, cmsInfo.getOtherStatusInfo().isExtendedFailInfo());

				byte[] b = cmsInfo.getEncoded();
				CMCStatusInfoV2 res = CMCStatusInfoV2.getInstance(b);

				isEquals("With optional info: ExtendedFailInfo", cmsInfo, res);

				isEquals("Must have other info", true, res.hasOtherInfo());
				isEquals("Other is extended fail info", true, res.getOtherStatusInfo().isExtendedFailInfo());
			}


		}
	}

}