using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Stream that outputs encoding based on definite length.
	/// </summary>
	public class DLOutputStream : ASN1OutputStream
	{
		public DLOutputStream(OutputStream os) : base(os)
		{
		}

		public override void writeObject(ASN1Encodable obj)
		{
			if (obj != null)
			{
				obj.toASN1Primitive().toDLObject().encode(this);
			}
			else
			{
				throw new IOException("null object detected");
			}
		}
	}

}