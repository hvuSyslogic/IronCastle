﻿using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A DER encoding version of an application specific object.
	/// </summary>
	public class DERApplicationSpecific : ASN1ApplicationSpecific
	{
		public DERApplicationSpecific(bool isConstructed, int tag, byte[] octets) : base(isConstructed, tag, octets)
		{
		}

		/// <summary>
		/// Create an application specific object from the passed in data. This will assume
		/// the data does not represent a constructed object.
		/// </summary>
		/// <param name="tag"> the tag number for this object. </param>
		/// <param name="octets"> the encoding of the object's body. </param>
		public DERApplicationSpecific(int tag, byte[] octets) : this(false, tag, octets)
		{
		}

		/// <summary>
		/// Create an application specific object with a tagging of explicit/constructed.
		/// </summary>
		/// <param name="tag"> the tag number for this object. </param>
		/// <param name="object"> the object to be contained. </param>
		public DERApplicationSpecific(int tag, ASN1Encodable @object) : this(true, tag, @object)
		{
		}

		/// <summary>
		/// Create an application specific object with the tagging style given by the value of constructed.
		/// </summary>
		/// <param name="constructed"> true if the object is constructed. </param>
		/// <param name="tag"> the tag number for this object. </param>
		/// <param name="object"> the object to be contained. </param>
		public DERApplicationSpecific(bool constructed, int tag, ASN1Encodable @object) : base(constructed || @object.toASN1Primitive().isConstructed(), tag, getEncoding(constructed, @object))
		{
		}

		private static byte[] getEncoding(bool @explicit, ASN1Encodable @object)
		{
			byte[] data = @object.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);

			if (@explicit)
			{
				return data;
			}
			else
			{
				int lenBytes = getLengthOfHeader(data);
				byte[] tmp = new byte[data.Length - lenBytes];
				JavaSystem.arraycopy(data, lenBytes, tmp, 0, tmp.Length);
				return tmp;
			}
		}

		/// <summary>
		/// Create an application specific object which is marked as constructed
		/// </summary>
		/// <param name="tagNo"> the tag number for this object. </param>
		/// <param name="vec"> the objects making up the application specific object. </param>
		public DERApplicationSpecific(int tagNo, ASN1EncodableVector vec) : base(true, tagNo, getEncodedVector(vec))
		{
		}

		private static byte[] getEncodedVector(ASN1EncodableVector vec)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			for (int i = 0; i != vec.size(); i++)
			{
				try
				{
					bOut.write(((ASN1Object)vec.get(i)).getEncoded(ASN1Encoding_Fields.DER));
				}
				catch (IOException e)
				{
					throw new ASN1ParsingException("malformed object: " + e, e);
				}
			}
			return bOut.toByteArray();
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
		 */
		public override void encode(ASN1OutputStream @out)
		{
			int classBits = BERTags_Fields.APPLICATION;
			if (isConstructed_Renamed)
			{
				classBits |= BERTags_Fields.CONSTRUCTED;
			}

			@out.writeEncoded(classBits, tag, octets);
		}
	}

}