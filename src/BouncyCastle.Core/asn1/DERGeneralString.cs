using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	/// <summary>
	/// ASN.1 GENERAL-STRING data type.
	/// <para>
	/// This is an 8-bit encoded ISO 646 (ASCII) character set
	/// with optional escapes to other character sets.
	/// </para>
	/// </summary>
	public class DERGeneralString : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// Return a GeneralString from the given object.
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERBMPString instance, or null. </returns>
		public static DERGeneralString getInstance(object obj)
		{
			if (obj == null || obj is DERGeneralString)
			{
				return (DERGeneralString) obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERGeneralString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return a GeneralString from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///              be converted. </exception>
		/// <returns> a DERGeneralString instance. </returns>
		public static DERGeneralString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERGeneralString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERGeneralString(((ASN1OctetString)o).getOctets());
			}
		}

		public DERGeneralString(byte[] @string)
		{
			this.@string = @string;
		}

		/// <summary>
		/// Construct a GeneralString from the passed in String.
		/// </summary>
		/// <param name="string"> the string to be contained in this object. </param>
		public DERGeneralString(string @string)
		{
			this.@string = Strings.toByteArray(@string);
		}

		/// <summary>
		/// Return a Java String representation of our contained String.
		/// </summary>
		/// <returns> a Java String representing our contents. </returns>
		public virtual string getString()
		{
			return Strings.fromByteArray(@string);
		}

		public override string ToString()
		{
			return getString();
		}

		/// <summary>
		/// Return a byte array representation of our contained String.
		/// </summary>
		/// <returns> a byte array representing our contents. </returns>
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
			@out.writeEncoded(BERTags_Fields.GENERAL_STRING, @string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERGeneralString))
			{
				return false;
			}
			DERGeneralString s = (DERGeneralString)o;

			return Arrays.areEqual(@string, s.@string);
		}
	}

}