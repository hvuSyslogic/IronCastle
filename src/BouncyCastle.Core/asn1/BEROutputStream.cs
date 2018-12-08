using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A class which writes indefinite and definite length objects. Objects which specify DER will be encoded accordingly, but DL or BER
	/// objects will be encoded as defined.
	/// </summary>
	public class BEROutputStream : DEROutputStream
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="os"> target output stream. </param>
		public BEROutputStream(OutputStream os) : base(os)
		{
		}

		/// <summary>
		/// Write out an ASN.1 object.
		/// </summary>
		/// <param name="obj"> the object to be encoded. </param>
		/// <exception cref="IOException"> if there is an issue on encoding or output of the object. </exception>
		public virtual void writeObject(object obj)
		{
			if (obj == null)
			{
				writeNull();
			}
			else if (obj is ASN1Primitive)
			{
				((ASN1Primitive)obj).encode(this);
			}
			else if (obj is ASN1Encodable)
			{
				((ASN1Encodable)obj).toASN1Primitive().encode(this);
			}
			else
			{
				throw new IOException("object not BEREncodable");
			}
		}
	}

}