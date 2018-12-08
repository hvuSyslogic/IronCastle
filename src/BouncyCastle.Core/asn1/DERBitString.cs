using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A BIT STRING with DER encoding - the first byte contains the count of padding bits included in the byte array's last byte.
	/// </summary>
	public class DERBitString : ASN1BitString
	{
		/// <summary>
		/// return a Bit String from the passed in object
		/// </summary>
		/// <param name="obj"> a DERBitString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERBitString instance, or null. </returns>
		public static DERBitString getInstance(object obj)
		{
			if (obj == null || obj is DERBitString)
			{
				return (DERBitString)obj;
			}
			if (obj is DLBitString)
			{
				return new DERBitString(((DLBitString)obj).data, ((DLBitString)obj).padBits);
			}
			if (obj is byte[])
			{
				try
				{
					return (DERBitString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// return a Bit String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERBitString instance, or null. </returns>
		public static DERBitString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERBitString)
			{
				return getInstance(o);
			}
			else
			{
				return fromOctetString(((ASN1OctetString)o).getOctets());
			}
		}

		public DERBitString(byte data, int padBits) : this(toByteArray(data), padBits)
		{
		}

		private static byte[] toByteArray(byte data)
		{
			byte[] rv = new byte[1];

			rv[0] = data;

			return rv;
		}

		/// <param name="data"> the octets making up the bit string. </param>
		/// <param name="padBits"> the number of extra bits at the end of the string. </param>
		public DERBitString(byte[] data, int padBits) : base(data, padBits)
		{
		}

		public DERBitString(byte[] data) : this(data, 0)
		{
		}

		public DERBitString(int value) : base(getBytes(value), getPadBits(value))
		{
		}

		public DERBitString(ASN1Encodable obj) : base(obj.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER), 0)
		{
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 1 + StreamUtil.calculateBodyLength(data.Length + 1) + data.Length + 1;
		}

		public override void encode(ASN1OutputStream @out)
		{
			byte[] @string = derForm(data, padBits);
			byte[] bytes = new byte[@string.Length + 1];

			bytes[0] = (byte)getPadBits();
			JavaSystem.arraycopy(@string, 0, bytes, 1, bytes.Length - 1);

			@out.writeEncoded(BERTags_Fields.BIT_STRING, bytes);
		}

		internal static DERBitString fromOctetString(byte[] bytes)
		{
			if (bytes.Length < 1)
			{
				throw new IllegalArgumentException("truncated BIT STRING detected");
			}

			int padBits = bytes[0];
			byte[] data = new byte[bytes.Length - 1];

			if (data.Length != 0)
			{
				JavaSystem.arraycopy(bytes, 1, data, 0, bytes.Length - 1);
			}

			return new DERBitString(data, padBits);
		}
	}

}