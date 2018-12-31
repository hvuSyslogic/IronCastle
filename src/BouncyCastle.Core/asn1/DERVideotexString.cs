using System;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

		
	public class DERVideotexString : ASN1Primitive, ASN1String
	{
		private readonly byte[] @string;

		/// <summary>
		/// return a Videotex String from the passed in object
		/// </summary>
		/// <param name="obj"> a DERVideotexString or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> a DERVideotexString instance, or null. </returns>
		public static DERVideotexString getInstance(object obj)
		{
			if (obj == null || obj is DERVideotexString)
			{
				return (DERVideotexString)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (DERVideotexString)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// return a Videotex String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> a DERVideotexString instance, or null. </returns>
		public static DERVideotexString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is DERVideotexString)
			{
				return getInstance(o);
			}
			else
			{
				return new DERVideotexString(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// basic constructor - with bytes. </summary>
		/// <param name="string"> the byte encoding of the characters making up the string. </param>
		public DERVideotexString(byte[] @string)
		{
			this.@string = Arrays.clone(@string);
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
			@out.writeEncoded(BERTags_Fields.VIDEOTEX_STRING, @string);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(@string);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is DERVideotexString))
			{
				return false;
			}

			DERVideotexString s = (DERVideotexString)o;

			return Arrays.areEqual(@string, s.@string);
		}

		public virtual string getString()
		{
			return Strings.fromByteArray(@string);
		}
	}

}