using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
	/// ASN.1 NUMERIC-STRING object.
	/// <para>
	/// This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
	/// </para>
	/// <para>
	/// See X.680 section 37.2.
	/// </para>
	/// <para>
	/// Explicit character set escape sequences are not allowed.
	/// </para>
	/// </summary>
	public class DERNumericString : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return a Numeric string from the passed in object
		/// </summary>
		/// <param name="obj"> a DERNumericString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERNumericString instance, or null </returns>
		public static DERNumericString getInstance(object obj)
		{
			if (obj == null || obj is DERNumericString)
			{
				return (DERNumericString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERNumericString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an Numeric String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERNumericString instance, or null. </returns>
		public static DERNumericString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERNumericString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERNumericString(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - with bytes.
		/// </summary>
		public DERNumericString(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor -  without validation..
		/// </summary>
		public DERNumericString(string @string) : this(@string, false)
		{
		}

		/// <summary>
		/// Constructor with optional validation.
		/// </summary>
		/// <param name="string"> the base string to wrap. </param>
		/// <param name="validate"> whether or not to check the string. </param>
		/// <exception cref="IllegalArgumentException"> if validate is true and the string
		/// contains characters that should not be in a NumericString. </exception>
		public DERNumericString(string @string, bool validate)
		{
			if (validate && !isNumericString(@string))
			{
				throw new IllegalArgumentException("string contains illegal characters");
			}

			this.@string = Strings.toByteArray(@string);
		}

		public virtual string getString()
		{
			return Strings.fromByteArray(@string);
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
			@out.writeEncoded(BERTags_Fields.NUMERIC_STRING, @string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERNumericString))
			{
				return false;
			}

			DERNumericString s = (DERNumericString)o;

			return Arrays.areEqual(@string, s.@string);
		}

		/// <summary>
		/// Return true if the string can be represented as a NumericString ('0'..'9', ' ')
		/// </summary>
		/// <param name="str"> string to validate. </param>
		/// <returns> true if numeric, fale otherwise. </returns>
		public static bool isNumericString(string str)
		{
			for (int i = str.Length - 1; i >= 0; i--)
			{
				char ch = str[i];

				if (ch > (char)0x007f)
				{
					return false;
				}

				if (('0' <= ch && ch <= '9') || ch == ' ')
				{
					continue;
				}

				return false;
			}

			return true;
		}
	}

}