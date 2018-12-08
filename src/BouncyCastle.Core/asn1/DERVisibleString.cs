using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
	/// <para>
	/// Explicit character set escape sequences are not allowed.
	/// </para>
	/// </summary>
	public class DERVisibleString : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return a Visible String from the passed in object.
		/// </summary>
		/// <param name="obj"> a DERVisibleString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERVisibleString instance, or null </returns>
		public static DERVisibleString getInstance(object obj)
		{
			if (obj == null || obj is DERVisibleString)
			{
				return (DERVisibleString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERVisibleString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return a Visible String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERVisibleString instance, or null </returns>
		public static DERVisibleString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERVisibleString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/*
		 * Basic constructor - byte encoded string.
		 */
		public DERVisibleString(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Basic constructor
		/// </summary>
		/// <param name="string"> the string to be carried in the VisibleString object, </param>
		public DERVisibleString(string @string)
		{
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
			@out.writeEncoded(BERTags_Fields.VISIBLE_STRING, this.@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERVisibleString))
			{
				return false;
			}

			return Arrays.areEqual(@string, ((DERVisibleString)o).@string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}
	}

}