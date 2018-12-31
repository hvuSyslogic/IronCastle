using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// DER T61String (also the teletex string) - a "modern" encapsulation that uses UTF-8. If at all possible, avoid this one! It's only for emergencies.
	/// Use UTF8String instead. </summary>
	/// @deprecated don't use this class, introduced in error, it will be removed. 
	public class DERT61UTF8String : ASN1Primitive, ASN1String
	{
		private byte[] @string;

		/// <summary>
		/// return a T61 string from the passed in object. UTF-8 Encoding is assumed in this case.
		/// </summary>
		/// <param name="obj"> a DERT61UTF8String or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERT61UTF8String instance, or null </returns>
		public static DERT61UTF8String getInstance(object obj)
		{
			if (obj is DERT61String)
			{
				return new DERT61UTF8String(((DERT61String)obj).getOctets());
			}

			if (obj == null || obj is DERT61UTF8String)
			{
				return (DERT61UTF8String)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return new DERT61UTF8String(((DERT61String)fromByteArray((byte[])obj)).getOctets());
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// return an T61 String from a tagged object. UTF-8 encoding is assumed in this case.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		/// be converted. </exception>
		/// <returns> a DERT61UTF8String instance, or null </returns>
		public static DERT61UTF8String getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERT61String || o is DERT61UTF8String)
			{
				return getInstance(o);
			}
			else
			{
				return new DERT61UTF8String(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// basic constructor - string encoded as a sequence of bytes.
		/// </summary>
		public DERT61UTF8String(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// basic constructor - with string UTF8 conversion assumed.
		/// </summary>
		public DERT61UTF8String(string @string) : this(Strings.toUTF8ByteArray(@string))
		{
		}

		/// <summary>
		/// Decode the encoded string and return it, UTF8 assumed.
		/// </summary>
		/// <returns> the decoded String </returns>
		public virtual string getString()
		{
			return Strings.fromUTF8ByteArray(@string);
		}

		public override string ToString()
		{
			return getString();
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
			@out.writeEncoded(BERTags_Fields.T61_STRING, @string);
		}

		/// <summary>
		/// Return the encoded string as a byte array.
		/// </summary>
		/// <returns> the actual bytes making up the encoded body of the T61 string. </returns>
		public virtual byte[] getOctets()
		{
			return Arrays.clone(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERT61UTF8String))
			{
				return false;
			}

			return Arrays.areEqual(@string, ((DERT61UTF8String)o).@string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}
	}

}