using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5084">RFC 5084</a>: GCMParameters object.
	/// <para>
	/// <pre>
	/// GCMParameters ::= SEQUENCE {
	///   aes-nonce        OCTET STRING, -- recommended size is 12 octets
	///   aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
	/// </pre>
	/// </para>
	/// </summary>
	public class GCMParameters : ASN1Object
	{
		private byte[] nonce;
		private int icvLen;

		/// <summary>
		/// Return an GCMParameters object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="org.bouncycastle.asn1.cms.GCMParameters"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence"/> input formats with GCMParameters structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static GCMParameters getInstance(object obj)
		{
			if (obj is GCMParameters)
			{
				return (GCMParameters)obj;
			}
			else if (obj != null)
			{
				return new GCMParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private GCMParameters(ASN1Sequence seq)
		{
			this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();

			if (seq.size() == 2)
			{
				this.icvLen = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue().intValue();
			}
			else
			{
				this.icvLen = 12;
			}
		}

		public GCMParameters(byte[] nonce, int icvLen)
		{
			this.nonce = Arrays.clone(nonce);
			this.icvLen = icvLen;
		}

		public virtual byte[] getNonce()
		{
			return Arrays.clone(nonce);
		}

		public virtual int getIcvLen()
		{
			return icvLen;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new DEROctetString(nonce));

			if (icvLen != 12)
			{
				v.add(new ASN1Integer(icvLen));
			}

			return new DERSequence(v);
		}
	}

}