using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// DER UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
	/// have no way of representing this directly so we rely on byte arrays to carry these.
	/// </summary>
	public class DERUniversalString : ASN1Primitive, ASN1String
	{
		private static readonly char[] table = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
		private readonly byte[] @string;

		/// <summary>
		/// Return a Universal String from the passed in object.
		/// </summary>
		/// <param name="obj"> a DERUniversalString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERUniversalString instance, or null </returns>
		public static DERUniversalString getInstance(object obj)
		{
			if (obj == null || obj is DERUniversalString)
			{
				return (DERUniversalString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERUniversalString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return a Universal String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERUniversalString instance, or null </returns>
		public static DERUniversalString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERUniversalString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERUniversalString(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - byte encoded string.
		/// </summary>
		/// <param name="string"> the byte encoding of the string to be carried in the UniversalString object, </param>
		public DERUniversalString(byte[] @string)
		{
			this.@string = Arrays.clone(@string);
		}

		public virtual string getString()
		{
			StringBuffer buf = new StringBuffer("#");
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			try
			{
				aOut.writeObject(this);
			}
			catch (IOException)
			{
			   throw new ASN1ParsingException("internal error encoding UniversalString");
			}

			byte[] @string = bOut.toByteArray();

			for (int i = 0; i != @string.Length; i++)
			{
				buf.append(table[((int)((uint)@string[i] >> 4)) & 0xf]);
				buf.append(table[@string[i] & 0xf]);
			}

			return buf.ToString();
		}

		public override string ToString()
		{
			return getString();
		}

		public virtual byte[] getOctets()
		{
			return Arrays.clone(@string);
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 1 + StreamUtil.calculateBodyLength(@string.Length) + @string.Length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.UNIVERSAL_STRING, this.getOctets());
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERUniversalString))
			{
				return false;
			}

			return Arrays.areEqual(@string, ((DERUniversalString)o).@string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}
	}

}