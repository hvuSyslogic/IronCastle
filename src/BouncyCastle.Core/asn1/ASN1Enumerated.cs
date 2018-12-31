using System;
using BouncyCastle.Core.custom;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// Class representing the ASN.1 ENUMERATED type.
	/// </summary>
	public class ASN1Enumerated : ASN1Primitive
	{
		private readonly byte[] bytes;

		/// <summary>
		/// return an enumerated from the passed in object
		/// </summary>
		/// <param name="obj"> an ASN1Enumerated or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> an ASN1Enumerated instance, or null. </returns>
		public static ASN1Enumerated getInstance(object obj)
		{
			if (obj == null || obj is ASN1Enumerated)
			{
				return (ASN1Enumerated)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (ASN1Enumerated)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// return an Enumerated from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> an ASN1Enumerated instance, or null. </returns>
		public static ASN1Enumerated getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1Enumerated)
			{
				return getInstance(o);
			}
			else
			{
				return fromOctetString(((ASN1OctetString)o).getOctets());
			}
		}

		/// <summary>
		/// Constructor from int.
		/// </summary>
		/// <param name="value"> the value of this enumerated. </param>
		public ASN1Enumerated(int value)
		{
			bytes = BigInteger.valueOf(value).toByteArray();
		}

		/// <summary>
		/// Constructor from BigInteger
		/// </summary>
		/// <param name="value"> the value of this enumerated. </param>
		public ASN1Enumerated(BigInteger value)
		{
			bytes = value.toByteArray();
		}

		/// <summary>
		/// Constructor from encoded BigInteger.
		/// </summary>
		/// <param name="bytes"> the value of this enumerated as an encoded BigInteger (signed). </param>
		public ASN1Enumerated(byte[] bytes)
		{
			if (!Properties.isOverrideSet("org.bouncycastle.asn1.allow_unsafe_integer"))
			{
				if (ASN1Integer.isMalformed(bytes))
				{
					throw new IllegalArgumentException("malformed enumerated");
				}
			}
			this.bytes = Arrays.clone(bytes);
		}

		public virtual BigInteger getValue()
		{
			return new BigInteger(bytes);
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 1 + StreamUtil.calculateBodyLength(bytes.Length) + bytes.Length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.ENUMERATED, bytes);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1Enumerated))
			{
				return false;
			}

			ASN1Enumerated other = (ASN1Enumerated)o;

			return Arrays.areEqual(this.bytes, other.bytes);
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(bytes);
		}

		private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

		internal static ASN1Enumerated fromOctetString(byte[] enc)
		{
			if (enc.Length > 1)
			{
				return new ASN1Enumerated(enc);
			}

			if (enc.Length == 0)
			{
				throw new IllegalArgumentException("ENUMERATED has zero length");
			}
			int value = enc[0] & 0xff;

			if (value >= cache.Length)
			{
				return new ASN1Enumerated(Arrays.clone(enc));
			}

			ASN1Enumerated possibleMatch = cache[value];

			if (possibleMatch == null)
			{
				possibleMatch = cache[value] = new ASN1Enumerated(Arrays.clone(enc));
			}

			return possibleMatch;
		}
	}

}