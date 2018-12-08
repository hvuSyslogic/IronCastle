using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Stream that outputs encoding based on distinguished encoding rules.
	/// </summary>
	public class DEROutputStream : ASN1OutputStream
	{
		public DEROutputStream(OutputStream os) : base(os)
		{
		}

		public override void writeObject(ASN1Encodable obj)
		{
			if (obj != null)
			{
				obj.toASN1Primitive().toDERObject().encode(this);
			}
			else
			{
				throw new IOException("null object detected");
			}
		}

		public override ASN1OutputStream getDERSubStream()
		{
			return this;
		}

		public override ASN1OutputStream getDLSubStream()
		{
			return this;
		}
	}

}