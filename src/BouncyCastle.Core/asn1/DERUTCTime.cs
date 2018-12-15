
using BouncyCastle.Core.Port.java.text;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// DER UTC time object.
	/// </summary>
	public class DERUTCTime : ASN1UTCTime
	{
		public DERUTCTime(byte[] bytes) : base(bytes)
		{
		}

		public DERUTCTime(DateTime time) : base(time)
		{
		}

		public DERUTCTime(string time) : base(time)
		{
		}

		// TODO: create proper DER encoding.
	}

}