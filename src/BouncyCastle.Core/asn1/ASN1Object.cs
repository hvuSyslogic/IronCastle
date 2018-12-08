using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Base class for defining an ASN.1 object.
	/// </summary>
	public abstract class ASN1Object : ASN1Encodable, Encodable
	{
		/// <summary>
		/// Return the default BER or DER encoding for this object.
		/// </summary>
		/// <returns> BER/DER byte encoded object. </returns>
		/// <exception cref="IOException"> on encoding error. </exception>
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			aOut.writeObject(this);

			return bOut.toByteArray();
		}

		/// <summary>
		/// Return either the default for "BER" or a DER encoding if "DER" is specified.
		/// </summary>
		/// <param name="encoding"> name of encoding to use. </param>
		/// <returns> byte encoded object. </returns>
		/// <exception cref="IOException"> on encoding error. </exception>
		public virtual byte[] getEncoded(string encoding)
		{
			if (encoding.Equals(ASN1Encoding_Fields.DER))
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DEROutputStream dOut = new DEROutputStream(bOut);

				dOut.writeObject(this);

				return bOut.toByteArray();
			}
			else if (encoding.Equals(ASN1Encoding_Fields.DL))
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DLOutputStream dOut = new DLOutputStream(bOut);

				dOut.writeObject(this);

				return bOut.toByteArray();
			}

			return this.getEncoded();
		}

		public override int GetHashCode()
		{
			return this.toASN1Primitive().GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is ASN1Encodable))
			{
				return false;
			}

			ASN1Encodable other = (ASN1Encodable)o;

			return this.toASN1Primitive().Equals(other.toASN1Primitive());
		}

		/// @deprecated use toASN1Primitive() 
		/// <returns> the underlying primitive type. </returns>
		public virtual ASN1Primitive toASN1Object()
		{
			return this.toASN1Primitive();
		}

		/// <summary>
		/// Return true if obj is a byte array and represents an object with the given tag value.
		/// </summary>
		/// <param name="obj"> object of interest. </param>
		/// <param name="tagValue"> tag value to check for. </param>
		/// <returns>  true if obj is a byte encoding starting with the given tag value, false otherwise. </returns>
		protected internal static bool hasEncodedTagValue(object obj, int tagValue)
		{
			return (obj is byte[]) && ((byte[])obj)[0] == tagValue;
		}

		/// <summary>
		/// Method providing a primitive representation of this object suitable for encoding. </summary>
		/// <returns> a primitive representation of this object. </returns>
		public abstract ASN1Primitive toASN1Primitive();
	}

}