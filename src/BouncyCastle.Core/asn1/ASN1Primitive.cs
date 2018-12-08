using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Base class for ASN.1 primitive objects. These are the actual objects used to generate byte encodings.
	/// </summary>
	public abstract class ASN1Primitive : ASN1Object
	{
		public ASN1Primitive()
		{

		}

		/// <summary>
		/// Create a base ASN.1 object from a byte stream.
		/// </summary>
		/// <param name="data"> the byte stream to parse. </param>
		/// <returns> the base ASN.1 object represented by the byte stream. </returns>
		/// <exception cref="IOException"> if there is a problem parsing the data, or parsing the stream did not exhaust the available data. </exception>
		public static ASN1Primitive fromByteArray(byte[] data)
		{
			ASN1InputStream aIn = new ASN1InputStream(data);

			try
			{
				ASN1Primitive o = aIn.readObject();

				if (aIn.available() != 0)
				{
					throw new IOException("Extra data detected in stream");
				}

				return o;
			}
			catch (ClassCastException)
			{
				throw new IOException("cannot recognise object in stream");
			}
		}

		public sealed override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			return (o is ASN1Encodable) && asn1Equals(((ASN1Encodable)o).toASN1Primitive());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return this;
		}

		/// <summary>
		/// Return the current object as one which encodes using Distinguished Encoding Rules.
		/// </summary>
		/// <returns> a DER version of this. </returns>
		public virtual ASN1Primitive toDERObject()
		{
			return this;
		}

		/// <summary>
		/// Return the current object as one which encodes using Definite Length encoding.
		/// </summary>
		/// <returns> a DL version of this. </returns>
		public virtual ASN1Primitive toDLObject()
		{
			return this;
		}

		public override abstract int GetHashCode();

		/// <summary>
		/// Return true if this objected is a CONSTRUCTED one, false otherwise. </summary>
		/// <returns> true if CONSTRUCTED bit set on object's tag, false otherwise. </returns>
		public abstract bool isConstructed();

		/// <summary>
		/// Return the length of the encoding this object will produce. </summary>
		/// <returns> the length of the object's encoding. </returns>
		/// <exception cref="IOException"> if the encoding length cannot be calculated. </exception>
		public abstract int encodedLength();

		public abstract void encode(ASN1OutputStream @out);

		/// <summary>
		/// Equality (similarity) comparison for two ASN1Primitive objects.
		/// </summary>
		public abstract bool asn1Equals(ASN1Primitive o);
	}
}