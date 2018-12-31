using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// DER PrintableString object.
	/// <para>
	/// X.680 section 37.4 defines PrintableString character codes as ASCII subset of following characters:
	/// </para>
	/// <ul>
	/// <li>Latin capital letters: 'A' .. 'Z'</li>
	/// <li>Latin small letters: 'a' .. 'z'</li>
	/// <li>Digits: '0'..'9'</li>
	/// <li>Space</li>
	/// <li>Apostrophe: '\''</li>
	/// <li>Left parenthesis: '('</li>
	/// <li>Right parenthesis: ')'</li>
	/// <li>Plus sign: '+'</li>
	/// <li>Comma: ','</li>
	/// <li>Hyphen-minus: '-'</li>
	/// <li>Full stop: '.'</li>
	/// <li>Solidus: '/'</li>
	/// <li>Colon: ':'</li>
	/// <li>Equals sign: '='</li>
	/// <li>Question mark: '?'</li>
	/// </ul>
	/// <para>
	/// Explicit character set escape sequences are not allowed.
	/// </para>
	/// </summary>
	public class DERPrintableString : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return a printable string from the passed in object.
		/// </summary>
		/// <param name="obj"> a DERPrintableString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERPrintableString instance, or null. </returns>
		public static DERPrintableString getInstance(object obj)
		{
			if (obj == null || obj is DERPrintableString)
			{
				return (DERPrintableString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERPrintableString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return a Printable String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERPrintableString instance, or null. </returns>
		public static DERPrintableString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERPrintableString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERPrintableString(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// Basic constructor - byte encoded string.
		/// </summary>
		public DERPrintableString(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor - this does not validate the string
		/// </summary>
		public DERPrintableString(string @string) : this(@string, false)
		{
		}

		/// <summary>
		/// Constructor with optional validation.
		/// </summary>
		/// <param name="string"> the base string to wrap. </param>
		/// <param name="validate"> whether or not to check the string. </param>
		/// <exception cref="IllegalArgumentException"> if validate is true and the string
		/// contains characters that should not be in a PrintableString. </exception>
		public DERPrintableString(string @string, bool validate)
		{
			if (validate && !isPrintableString(@string))
			{
				throw new IllegalArgumentException("string contains illegal characters");
			}

			this.@string = Strings.toByteArray(@string);
		}

		public virtual string getString()
		{
			return Strings.fromByteArray(@string);
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
			@out.writeEncoded(BERTags_Fields.PRINTABLE_STRING, @string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERPrintableString))
			{
				return false;
			}

			DERPrintableString s = (DERPrintableString)o;

			return Arrays.areEqual(@string, s.@string);
		}

		public override string ToString()
		{
			return getString();
		}

		/// <summary>
		/// return true if the passed in String can be represented without
		/// loss as a PrintableString, false otherwise.
		/// </summary>
		/// <returns> true if in printable set, false otherwise. </returns>
		public static bool isPrintableString(string str)
		{
			for (int i = str.Length - 1; i >= 0; i--)
			{
				char ch = str[i];

				if (ch > (char)0x007f)
				{
					return false;
				}

				if ('a' <= ch && ch <= 'z')
				{
					continue;
				}

				if ('A' <= ch && ch <= 'Z')
				{
					continue;
				}

				if ('0' <= ch && ch <= '9')
				{
					continue;
				}

				switch (ch)
				{
				case ' ':
				case '\'':
				case '(':
				case ')':
				case '+':
				case '-':
				case '.':
				case ':':
				case '=':
				case '?':
				case '/':
				case ',':
					continue;
				}

				return false;
			}

			return true;
		}
	}

}