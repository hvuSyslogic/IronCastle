using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{

	using CMCFailInfo = org.bouncycastle.asn1.cmc.CMCFailInfo;
	using ExtendedFailInfo = org.bouncycastle.asn1.cmc.ExtendedFailInfo;
	using OtherStatusInfo = org.bouncycastle.asn1.cmc.OtherStatusInfo;
	using PendInfo = org.bouncycastle.asn1.cmc.PendInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class OtherStatusInfoTest : SimpleTest
	{
		public static void Main(string[] args)
		{
			runTest(new OtherStatusInfoTest());
		}

		public override string getName()
		{
			return "OtherStatusInfoTest";
		}

		public override void performTest()
		{
			{
				OtherStatusInfo ose = OtherStatusInfo.getInstance(CMCFailInfo.badCertId.toASN1Primitive());
				byte[] b = ose.getEncoded();
				OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

				isEquals("isFailInfo", oseResult.isFailInfo(), true);
				isEquals("isPendInfo", oseResult.isPendingInfo(), false);
				isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), false);

				isEquals(ose, oseResult);
			}

			{
				OtherStatusInfo ose = OtherStatusInfo.getInstance(new PendInfo("Fish".GetBytes(), new ASN1GeneralizedTime(DateTime.Now)));
				byte[] b = ose.getEncoded();
				OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

				isEquals("isFailInfo", oseResult.isFailInfo(), false);
				isEquals("isPendInfo", oseResult.isPendingInfo(), true);
				isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), false);

				isEquals(ose, oseResult);
			}

			{
				OtherStatusInfo ose = OtherStatusInfo.getInstance(new ExtendedFailInfo(PKCSObjectIdentifiers_Fields.canNotDecryptAny, new ASN1Integer(10L)));
				byte[] b = ose.getEncoded();
				OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

				isEquals("isFailInfo", oseResult.isFailInfo(), false);
				isEquals("isPendInfo", oseResult.isPendingInfo(), false);
				isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), true);

				isEquals(ose, oseResult);
			}
		}
	}

}