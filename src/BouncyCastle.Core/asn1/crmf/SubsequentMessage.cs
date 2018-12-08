using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{

	public class SubsequentMessage : ASN1Integer
	{
		public static readonly SubsequentMessage encrCert = new SubsequentMessage(0);
		public static readonly SubsequentMessage challengeResp = new SubsequentMessage(1);

		private SubsequentMessage(int value) : base(value)
		{
		}

		public static SubsequentMessage valueOf(int value)
		{
			if (value == 0)
			{
				return encrCert;
			}
			if (value == 1)
			{
				return challengeResp;
			}

			throw new IllegalArgumentException("unknown value: " + value);
		}
	}

}