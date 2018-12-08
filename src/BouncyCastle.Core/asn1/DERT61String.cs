using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// DER T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
	/// this has been withdrawn.
	/// </summary>
	public class DERT61String : ASN1Primitive, ASN1String
	{
		private byte[] @string;

		/// <summary>
		/// Return a T61 string from the passed in object.
		/// </summary>
		/// <param name="obj"> a DERT61String or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERT61String instance, or null </returns>
		public static DERT61String getInstance(object obj)
		{
			if (obj == null || obj is DERT61String)
			{
				return (DERT61String)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERT61String)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an T61 String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERT61String instance, or null </returns>
		public static DERT61String getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERT61String)
			{
				return getInstance(o);
			}
			else
			{
				return new DERT61String(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - string encoded as a sequence of bytes.
		/// </summary>
		/// <param name="string"> the byte encoding of the string to be wrapped. </param>
		public DERT61String(byte[] @string)
		{
			this.@string = Arrays.clone(@string);
		}

		/// <summary>
		/// Basic constructor - with string 8 bit assumed.
		/// </summary>
		/// <param name="string"> the string to be wrapped. </param>
		public DERT61String(string @string)
		{
			this.@string = Strings.toByteArray(@string);
		}

		/// <summary>
		/// Decode the encoded string and return it, 8 bit encoding assumed. </summary>
		/// <returns> the decoded String </returns>
		public virtual string getString()
		{
			return Strings.fromByteArray(@string);
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
		/// Return the encoded string as a byte array. </summary>
		/// <returns> the actual bytes making up the encoded body of the T61 string. </returns>
		public virtual byte[] getOctets()
		{
			return Arrays.clone(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERT61String))
			{
				return false;
			}

			return Arrays.areEqual(@string, ((DERT61String)o).@string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}
	}

}