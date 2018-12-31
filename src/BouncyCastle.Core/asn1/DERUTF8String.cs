using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// DER UTF8String object.
	/// </summary>
	public class DERUTF8String : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return an UTF8 string from the passed in object.
		/// </summary>
		/// <param name="obj"> a DERUTF8String or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException">
		///                if the object cannot be converted. </exception>
		/// <returns> a DERUTF8String instance, or null </returns>
		public static DERUTF8String getInstance(object obj)
		{
			if (obj == null || obj is DERUTF8String)
			{
				return (DERUTF8String)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERUTF8String)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an UTF8 String from a tagged object.
		/// </summary>
		/// <param name="obj">
		///            the tagged object holding the object we want </param>
		/// <param name="explicit">
		///            true if the object is meant to be explicitly tagged false
		///            otherwise. </param>
		/// <exception cref="IllegalArgumentException">
		///                if the tagged object cannot be converted. </exception>
		/// <returns> a DERUTF8String instance, or null </returns>
		public static DERUTF8String getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERUTF8String)
			{
				return getInstance(o);
			}
			else
			{
				return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/*
		 * Basic constructor - byte encoded string.
		 */
		public DERUTF8String(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor
		/// </summary>
		/// <param name="string"> the string to be carried in the UTF8String object, </param>
		public DERUTF8String(string @string)
		{
			this.@string = Strings.toUTF8ByteArray(@string);
		}

		public virtual string getString()
		{
			return Strings.fromUTF8ByteArray(@string);
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
			if (!(o is DERUTF8String))
			{
				return false;
			}

			DERUTF8String s = (DERUTF8String)o;

			return Arrays.areEqual(@string, s.@string);
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
			@out.writeEncoded(BERTags_Fields.UTF8_STRING, @string);
		}
	}

}