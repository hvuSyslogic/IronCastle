namespace org.bouncycastle.asn1
{
	/// @deprecated use ASN1Boolean 
	public class DERBoolean : ASN1Boolean
	{
		/// @deprecated use getInstance(boolean) method. 
		/// <param name="value"> </param>
		public DERBoolean(bool value) : base(value)
		{
		}

		public DERBoolean(byte[] value) : base(value)
		{
		}
	}

}