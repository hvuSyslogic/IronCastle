using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1
{

	/// @deprecated Use ASN1Enumerated instead of this. 
	public class DEREnumerated : ASN1Enumerated
	{
		/// <param name="bytes"> the value of this enumerated as an encoded BigInteger (signed). </param>
		/// @deprecated use ASN1Enumerated 
		public DEREnumerated(byte[] bytes) : base(bytes)
		{
		}

		/// <param name="value"> the value of this enumerated. </param>
		/// @deprecated use ASN1Enumerated 
		public DEREnumerated(BigInteger value) : base(value)
		{
		}

		/// <param name="value"> the value of this enumerated. </param>
		/// @deprecated use ASN1Enumerated 
		public DEREnumerated(int value) : base(value)
		{
		}
	}

}