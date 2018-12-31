using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// DER BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
	/// (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
	/// <para>
	/// At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
	/// term "UCS-2".
	/// </para>
	/// </summary>
	public class DERBMPString : ASN1Primitive, ASN1String
	{
		private readonly char[] @string;

		/// <summary>
		/// Return a BMP String from the given object.
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERBMPString instance, or null. </returns>
		public static DERBMPString getInstance(object obj)
		{
			if (obj == null || obj is DERBMPString)
			{
				return (DERBMPString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERBMPString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return a BMP String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///              be converted. </exception>
		/// <returns> a DERBMPString instance. </returns>
		public static DERBMPString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERBMPString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - byte encoded string. </summary>
		/// <param name="string"> the encoded BMP STRING to wrap. </param>
		public DERBMPString(byte[] @string)
		{
			char[] cs = new char[@string.Length / 2];

			for (int i = 0; i != cs.Length; i++)
			{
				cs[i] = (char)((@string[2 * i] << 8) | (@string[2 * i + 1] & 0xff));
			}

			this.@string = cs;
		}

		public DERBMPString(char[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor </summary>
		/// <param name="string"> a String to wrap as a BMP STRING. </param>
		public DERBMPString(string @string)
		{
			this.@string = @string.ToCharArray();
		}

		public virtual string getString()
		{
			return new string(@string);
		}

		public override string ToString()
		{
			return getString();
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERBMPString))
			{
				return false;
			}

			DERBMPString s = (DERBMPString)o;

			return Arrays.areEqual(@string, s.@string);
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 1 + StreamUtil.calculateBodyLength(@string.Length * 2) + (@string.Length * 2);
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.write(BERTags_Fields.BMP_STRING);
			@out.writeLength(@string.Length * 2);

			for (int i = 0; i != @string.Length; i++)
			{
				char c = @string[i];

				@out.write((byte)(c >> 8));
				@out.write((byte)c);
			}
		}
	}

}