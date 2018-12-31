using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// DER IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
	/// <para>
	/// Explicit character set escape sequences are not allowed.
	/// </para>
	/// </summary>
	public class DERIA5String : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return an IA5 string from the passed in object
		/// </summary>
		/// <param name="obj"> a DERIA5String or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERIA5String instance, or null. </returns>
		public static DERIA5String getInstance(object obj)
		{
			if (obj == null || obj is DERIA5String)
			{
				return (DERIA5String)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERIA5String)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an IA5 String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERIA5String instance, or null. </returns>
		public static DERIA5String getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERIA5String)
			{
				return getInstance(o);
			}
			else
			{
				return new DERIA5String(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - with bytes. </summary>
		/// <param name="string"> the byte encoding of the characters making up the string. </param>
		public DERIA5String(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor - without validation. </summary>
		/// <param name="string"> the base string to use.. </param>
		public DERIA5String(string @string) : this(@string, false)
		{
		}

		/// <summary>
		/// Constructor with optional validation.
		/// </summary>
		/// <param name="string"> the base string to wrap. </param>
		/// <param name="validate"> whether or not to check the string. </param>
		/// <exception cref="IllegalArgumentException"> if validate is true and the string
		/// contains characters that should not be in an IA5String. </exception>
		public DERIA5String(string @string, bool validate)
		{
			if (string.ReferenceEquals(@string, null))
			{
				throw new NullPointerException("string cannot be null");
			}
			if (validate && !isIA5String(@string))
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
			@out.writeEncoded(BERTags_Fields.IA5_STRING, @string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERIA5String))
			{
				return false;
			}

			DERIA5String s = (DERIA5String)o;

			return Arrays.areEqual(@string, s.@string);
		}

		/// <summary>
		/// return true if the passed in String can be represented without
		/// loss as an IA5String, false otherwise.
		/// </summary>
		/// <param name="str"> the string to check. </param>
		/// <returns> true if character set in IA5String set, false otherwise. </returns>
		public static bool isIA5String(string str)
		{
			for (int i = str.Length - 1; i >= 0; i--)
			{
				char ch = str[i];

				if (ch > (char)0x007f)
				{
					return false;
				}
			}

			return true;
		}
	}

}