using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1
{

	/// @deprecated  Use ASN1Integer instead of this, 
	public class DERInteger : ASN1Integer
	{
		/// <summary>
		/// Constructor from a byte array containing a signed representation of the number.
		/// </summary>
		/// <param name="bytes"> a byte array containing the signed number.A copy is made of the byte array. </param>
		public DERInteger(byte[] bytes) : base(bytes, true)
		{
		}

		public DERInteger(BigInteger value) : base(value)
		{
		}

		public DERInteger(long value) : base(value)
		{
		}
	}

}