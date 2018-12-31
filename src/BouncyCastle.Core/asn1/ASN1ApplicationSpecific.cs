using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// Base class for an ASN.1 ApplicationSpecific object
	/// </summary>
	public abstract class ASN1ApplicationSpecific : ASN1Primitive
	{
		protected internal readonly bool isConstructed_Renamed;
		protected internal readonly int tag;
		protected internal readonly byte[] octets;

		public ASN1ApplicationSpecific(bool isConstructed, int tag, byte[] octets)
		{
			this.isConstructed_Renamed = isConstructed;
			this.tag = tag;
			this.octets = Arrays.clone(octets);
		}

		/// <summary>
		/// Return an ASN1ApplicationSpecific from the passed in object, which may be a byte array, or null.
		/// </summary>
		/// <param name="obj"> the object to be converted. </param>
		/// <returns> obj's representation as an ASN1ApplicationSpecific object. </returns>
		public static ASN1ApplicationSpecific getInstance(object obj)
		{
			if (obj == null || obj is ASN1ApplicationSpecific)
			{
				return (ASN1ApplicationSpecific)obj;
			}
			else if (obj is byte[])
			{
				try
				{
					return ASN1ApplicationSpecific.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("Failed to construct object from byte[]: " + e.Message);
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		protected internal static int getLengthOfHeader(byte[] data)
		{
			int length = data[1] & 0xff; // TODO: assumes 1 byte tag

			if (length == 0x80)
			{
				return 2; // indefinite-length encoding
			}

			if (length > 127)
			{
				int size = length & 0x7f;

				// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
				if (size > 4)
				{
					throw new IllegalStateException("DER length more than 4 bytes: " + size);
				}

				return size + 2;
			}

			return 2;
		}

		/// <summary>
		/// Return true if the object is marked as constructed, false otherwise.
		/// </summary>
		/// <returns> true if constructed, otherwise false. </returns>
		public override bool isConstructed()
		{
			return isConstructed_Renamed;
		}

		/// <summary>
		/// Return the contents of this object as a byte[]
		/// </summary>
		/// <returns> the encoded contents of the object. </returns>
		public virtual byte[] getContents()
		{
			return Arrays.clone(octets);
		}

		/// <summary>
		/// Return the tag number associated with this object,
		/// </summary>
		/// <returns> the application tag number. </returns>
		public virtual int getApplicationTag()
		{
			return tag;
		}

		/// <summary>
		/// Return the enclosed object assuming explicit tagging.
		/// </summary>
		/// <returns>  the resulting object </returns>
		/// <exception cref="IOException"> if reconstruction fails. </exception>
		public virtual ASN1Primitive getObject()
		{
			return ASN1Primitive.fromByteArray(getContents());
		}

		/// <summary>
		/// Return the enclosed object assuming implicit tagging.
		/// </summary>
		/// <param name="derTagNo"> the type tag that should be applied to the object's contents. </param>
		/// <returns>  the resulting object </returns>
		/// <exception cref="IOException"> if reconstruction fails. </exception>
		public virtual ASN1Primitive getObject(int derTagNo)
		{
			if (derTagNo >= 0x1f)
			{
				throw new IOException("unsupported tag number");
			}

			byte[] orig = this.getEncoded();
			byte[] tmp = replaceTagNumber(derTagNo, orig);

			if ((orig[0] & BERTags_Fields.CONSTRUCTED) != 0)
			{
				tmp[0] |= BERTags_Fields.CONSTRUCTED;
			}

			return ASN1Primitive.fromByteArray(tmp);
		}

		public override int encodedLength()
		{
			return StreamUtil.calculateTagLength(tag) + StreamUtil.calculateBodyLength(octets.Length) + octets.Length;
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

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1ApplicationSpecific))
			{
				return false;
			}

			ASN1ApplicationSpecific other = (ASN1ApplicationSpecific)o;

			return isConstructed_Renamed == other.isConstructed_Renamed && tag == other.tag && Arrays.areEqual(octets, other.octets);
		}

		public override int GetHashCode()
		{
			return (isConstructed_Renamed ? 1 : 0) ^ tag ^ Arrays.GetHashCode(octets);
		}

		private byte[] replaceTagNumber(int newTag, byte[] input)
		{
			int tagNo = input[0] & 0x1f;
			int index = 1;
			//
			// with tagged object tag number is bottom 5 bits, or stored at the start of the content
			//
			if (tagNo == 0x1f)
			{
				int b = input[index++] & 0xff;

				// X.690-0207 8.1.2.4.2
				// "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
				if ((b & 0x7f) == 0) // Note: -1 will pass
				{
					throw new IOException("corrupted stream - invalid high tag number found");
				}

				while ((b & 0x80) != 0)
				{
					b = input[index++] & 0xff;
				}
			}

			byte[] tmp = new byte[input.Length - index + 1];

		   JavaSystem.arraycopy(input, index, tmp, 1, tmp.Length - 1);

			tmp[0] = (byte)newTag;

			return tmp;
		}

		public override string ToString()
		{
			StringBuffer sb = new StringBuffer();
			sb.append("[");
			if (isConstructed())
			{
				sb.append("CONSTRUCTED ");
			}
			sb.append("APPLICATION ");
			sb.append(Convert.ToString(getApplicationTag()));
			sb.append("]");
			// @todo content encoding somehow?
			if (this.octets != null)
			{
				sb.append(" #");
				sb.append(Hex.toHexString(this.octets));
			}
			else
			{
				sb.append(" #null");
			}
			sb.append(" ");
			return sb.ToString();
		}
	}

}