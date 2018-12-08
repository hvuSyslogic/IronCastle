using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.util
{

	/// @deprecated use ASN1Dump. 
	public class DERDump : ASN1Dump
	{
		/// <summary>
		/// dump out a DER object as a formatted string
		/// </summary>
		/// <param name="obj"> the ASN1Primitive to be dumped out. </param>
		public static string dumpAsString(ASN1Primitive obj)
		{
			StringBuffer buf = new StringBuffer();

			_dumpAsString("", false, obj, buf);

			return buf.ToString();
		}

		/// <summary>
		/// dump out a DER object as a formatted string
		/// </summary>
		/// <param name="obj"> the ASN1Primitive to be dumped out. </param>
		public static string dumpAsString(ASN1Encodable obj)
		{
			StringBuffer buf = new StringBuffer();

			_dumpAsString("", false, obj.toASN1Primitive(), buf);

			return buf.ToString();
		}
	}

}