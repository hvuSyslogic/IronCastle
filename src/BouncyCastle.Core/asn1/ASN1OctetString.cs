using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Abstract base for the ASN.1 OCTET STRING data type
	/// <para>
	/// This supports BER, and DER forms of the data.
	/// </para>
	/// </para><para>
	/// DER form is always primitive single OCTET STRING, while
	/// BER support includes the constructed forms.
	/// </p>
	/// <para><b>X.690</b></para>
	/// <para><b>8: Basic encoding rules</b></para>
	/// <para><b>8.7 Encoding of an octetstring value</b></para>
	/// <para>
	/// <b>8.7.1</b> The encoding of an octetstring value shall be
	/// either primitive or constructed at the option of the sender.
	/// <blockquote>
	/// NOTE &mdash; Where it is necessary to transfer part of an octet string
	/// before the entire OCTET STRING is available, the constructed encoding
	/// is used.
	/// </blockquote>
	/// </para>
	/// <para>
	/// <b>8.7.2</b> The primitive encoding contains zero,
	/// one or more contents octets equal in value to the octets
	/// in the data value, in the order they appear in the data value,
	/// and with the most significant bit of an octet of the data value
	/// aligned with the most significant bit of an octet of the contents octets.
	/// </para>
	/// <para>
	/// <b>8.7.3</b> The contents octets for the constructed encoding shall consist
	/// of zero, one, or more encodings.
	/// </para>
	/// <blockquote>
	/// NOTE &mdash; Each such encoding includes identifier, length, and contents octets,
	/// and may include end-of-contents octets if it is constructed.
	/// </blockquote>
	/// <para>
	/// <b>8.7.3.1</b> To encode an octetstring value in this way,
	/// it is segmented. Each segment shall consist of a series of
	/// consecutive octets of the value. There shall be no significance
	/// placed on the segment boundaries.</para>
	/// <blockquote>
	/// NOTE &mdash; A segment may be of size zero, i.e. contain no octets.
	/// </blockquote>
	/// <para>
	/// <b>8.7.3.2</b> Each encoding in the contents octets shall represent
	/// a segment of the overall octetstring, the encoding arising from
	/// a recursive application of this subclause.
	/// In this recursive application, each segment is treated as if it were
	/// a octetstring value. The encodings of the segments shall appear in the contents
	/// octets in the order in which their octets appear in the overall value.
	/// </para>
	/// <blockquote>
	/// NOTE 1 &mdash; As a consequence of this recursion,
	/// each encoding in the contents octets may itself
	/// be primitive or constructed.
	/// However, such encodings will usually be primitive.
	/// </blockquote>
	/// <blockquote>
	/// NOTE 2 &mdash; In particular, the tags in the contents octets are always universal class, number 4.
	/// </blockquote>
	/// <para><b>9: Canonical encoding rules</b></para>
	/// <para><b>9.1 Length forms</b></para>
	/// <para>
	/// If the encoding is constructed, it shall employ the indefinite-length form.
	/// If the encoding is primitive, it shall include the fewest length octets necessary.
	/// [Contrast with 8.1.3.2 b).]
	/// </para>
	/// <para><b>9.2 String encoding forms</b></para>
	/// <para>
	/// BIT STRING, OCTET STRING,and restricted character string
	/// values shall be encoded with a primitive encoding if they would
	/// require no more than 1000 contents octets, and as a constructed
	/// encoding otherwise. The string fragments contained in
	/// the constructed encoding shall be encoded with a primitive encoding.
	/// The encoding of each fragment, except possibly
	/// the last, shall have 1000 contents octets. (Contrast with 8.21.6.)
	/// </para>
	/// </para><para>
	/// <b>10: Distinguished encoding rules</b>
	/// </para><para>
	/// <b>10.1 Length forms</b>
	/// The definite form of length encoding shall be used,
	/// encoded in the minimum number of octets.
	/// [Contrast with 8.1.3.2 b).] 
	/// </para><para>
	/// <b>10.2 String encoding forms</b>
	/// For BIT STRING, OCTET STRING and restricted character string types,
	/// the constructed form of encoding shall not be used.
	/// (Contrast with 8.21.6.)
	/// </summary>
	public abstract class ASN1OctetString : ASN1Primitive, ASN1OctetStringParser
	{
		internal byte[] @string;

		/// <summary>
		/// return an Octet String from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///              be converted. </exception>
		public static ASN1OctetString getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1OctetString)
			{
				return getInstance(o);
			}
			else
			{
				return BEROctetString.fromSequence(ASN1Sequence.getInstance(o));
			}
		}

		/// <summary>
		/// return an Octet String from the given object.
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ASN1OctetString getInstance(object obj)
		{
			if (obj == null || obj is ASN1OctetString)
			{
				return (ASN1OctetString)obj;
			}
			else if (obj is byte[])
			{
				try
				{
					return ASN1OctetString.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct OCTET STRING from byte[]: " + e.Message);
				}
			}
			else if (obj is ASN1Encodable)
			{
				ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

				if (primitive is ASN1OctetString)
				{
					return (ASN1OctetString)primitive;
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="string"> the octets making up the octet string. </param>
		public ASN1OctetString(byte[] @string)
		{
			if (@string == null)
			{
				throw new NullPointerException("string cannot be null");
			}
			this.@string = @string;
		}

		/// <summary>
		/// Return the content of the OCTET STRING as an InputStream.
		/// </summary>
		/// <returns> an InputStream representing the OCTET STRING's content. </returns>
		public virtual InputStream getOctetStream()
		{
			return new ByteArrayInputStream(@string);
		}

		/// <summary>
		/// Return the parser associated with this object.
		/// </summary>
		/// <returns> a parser based on this OCTET STRING </returns>
		public virtual ASN1OctetStringParser parser()
		{
			return this;
		}

		/// <summary>
		/// Return the content of the OCTET STRING as a byte array.
		/// </summary>
		/// <returns> the byte[] representing the OCTET STRING's content. </returns>
		public virtual byte[] getOctets()
		{
			return @string;
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(this.getOctets());
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1OctetString))
			{
				return false;
			}

			ASN1OctetString other = (ASN1OctetString)o;

			return Arrays.areEqual(@string, other.@string);
		}

		public virtual ASN1Primitive getLoadedObject()
		{
			return this.toASN1Primitive();
		}

		public override ASN1Primitive toDERObject()
		{
			return new DEROctetString(@string);
		}

		public override ASN1Primitive toDLObject()
		{
			return new DEROctetString(@string);
		}

		public override abstract void encode(ASN1OutputStream @out);

		public override string ToString()
		{
		  return "#" + Strings.fromByteArray(Hex.encode(@string));
		}
	}

}