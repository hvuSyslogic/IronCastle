using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Properties = org.bouncycastle.util.Properties;

	/// <summary>
	/// Class representing the ASN.1 INTEGER type.
	/// </summary>
	public class ASN1Integer : ASN1Primitive
	{
		private readonly byte[] bytes;

		/// <summary>
		/// Return an integer from the passed in object.
		/// </summary>
		/// <param name="obj"> an ASN1Integer or an object that can be converted into one. </param>
		/// <returns> an ASN1Integer instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ASN1Integer getInstance(object obj)
		{
			if (obj == null || obj is ASN1Integer)
			{
				return (ASN1Integer)obj;
			}

			if (obj is byte[])
			{
				try
				{
					return (ASN1Integer)fromByteArray((byte[])obj);
				}
				catch (Exception e)
				{
					throw new IllegalArgumentException("encoding error in getInstance: " + e.ToString());
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an Integer from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <returns> an ASN1Integer instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		/// be converted. </exception>
		public static ASN1Integer getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1Integer)
			{
				return getInstance(o);
			}
			else
			{
				return new ASN1Integer(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		/// <summary>
		/// Construct an INTEGER from the passed in long value.
		/// </summary>
		/// <param name="value"> the long representing the value desired. </param>
		public ASN1Integer(long value)
		{
			bytes = BigInteger.valueOf(value).toByteArray();
		}

		/// <summary>
		/// Construct an INTEGER from the passed in BigInteger value.
		/// </summary>
		/// <param name="value"> the BigInteger representing the value desired. </param>
		public ASN1Integer(BigInteger value)
		{
			bytes = value.toByteArray();
		}

		/// <summary>
		/// Construct an INTEGER from the passed in byte array.
		/// 
		/// <para>
		/// <b>NB: Strict Validation applied by default.</b>
		/// </para>
		/// <para>
		/// It has turned out that there are still a few applications that struggle with
		/// the ASN.1 BER encoding rules for an INTEGER as described in:
		/// 
		/// https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
		/// Section 8.3.2.
		/// </para>
		/// <para>
		/// Users can set the 'org.bouncycastle.asn1.allow_unsafe_integer' to 'true'
		/// and a looser validation will be applied. Users must recognise that this is
		/// not ideal and may pave the way for an exploit based around a faulty encoding
		/// in the future.
		/// </para>
		/// </summary>
		/// <param name="bytes"> the byte array representing a 2's complement encoding of a BigInteger. </param>
		public ASN1Integer(byte[] bytes) : this(bytes, true)
		{
		}

		public ASN1Integer(byte[] bytes, bool clone)
		{
			// Apply loose validation, see note in public constructor ANS1Integer(byte[])
			if (!Properties.isOverrideSet("org.bouncycastle.asn1.allow_unsafe_integer"))
			{
				if (isMalformed(bytes))
				{
					throw new IllegalArgumentException("malformed integer");
				}
			}
			this.bytes = (clone) ? Arrays.clone(bytes) : bytes;
		}

		/// <summary>
		/// Apply the correct validation for an INTEGER primitive following the BER rules.
		/// </summary>
		/// <param name="bytes"> The raw encoding of the integer. </param>
		/// <returns> true if the (in)put fails this validation. </returns>
		internal static bool isMalformed(byte[] bytes)
		{
			if (bytes.Length > 1)
			{
				if (bytes[0] == 0 && (bytes[1] & 0x80) == 0)
				{
					return true;
				}
				if (bytes[0] == unchecked((byte)0xff) && (bytes[1] & 0x80) != 0)
				{
					return true;
				}
			}

			return false;
		}

		public virtual BigInteger getValue()
		{
			return new BigInteger(bytes);
		}

		/// <summary>
		/// in some cases positive values get crammed into a space,
		/// that's not quite big enough...
		/// </summary>
		/// <returns> the BigInteger that results from treating this ASN.1 INTEGER as unsigned. </returns>
		public virtual BigInteger getPositiveValue()
		{
			return new BigInteger(1, bytes);
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
			@out.writeEncoded(BERTags_Fields.INTEGER, bytes);
		}

		public override int GetHashCode()
		{
			int value = 0;

			for (int i = 0; i != bytes.Length; i++)
			{
				value ^= (bytes[i] & 0xff) << (i % 4);
			}

			return value;
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1Integer))
			{
				return false;
			}

			ASN1Integer other = (ASN1Integer)o;

			return Arrays.areEqual(bytes, other.bytes);
		}

		public override string ToString()
		{
			return getValue().ToString();
		}

	}

}