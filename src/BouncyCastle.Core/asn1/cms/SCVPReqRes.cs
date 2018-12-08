using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5940">RFC 5940</a>:
	/// Additional Cryptographic Message Syntax (CMS) Revocation Information Choices.
	/// <para>
	/// <pre>
	/// SCVPReqRes ::= SEQUENCE {
	///     request  [0] EXPLICIT ContentInfo OPTIONAL,
	///     response     ContentInfo }
	/// </pre>
	/// </para>
	/// </summary>
	public class SCVPReqRes : ASN1Object
	{
		private readonly ContentInfo request;
		private readonly ContentInfo response;

		/// <summary>
		/// Return a SCVPReqRes object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="SCVPReqRes"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with SCVPReqRes structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static SCVPReqRes getInstance(object obj)
		{
			if (obj is SCVPReqRes)
			{
				return (SCVPReqRes)obj;
			}
			else if (obj != null)
			{
				return new SCVPReqRes(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private SCVPReqRes(ASN1Sequence seq)
		{
			if (seq.getObjectAt(0) is ASN1TaggedObject)
			{
				this.request = ContentInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(0)), true);
				this.response = ContentInfo.getInstance(seq.getObjectAt(1));
			}
			else
			{
				this.request = null;
				this.response = ContentInfo.getInstance(seq.getObjectAt(0));
			}
		}

		public SCVPReqRes(ContentInfo response)
		{
			this.request = null; // use of this confuses earlier JDKs
			this.response = response;
		}

		public SCVPReqRes(ContentInfo request, ContentInfo response)
		{
			this.request = request;
			this.response = response;
		}

		public virtual ContentInfo getRequest()
		{
			return request;
		}

		public virtual ContentInfo getResponse()
		{
			return response;
		}

		/// <returns>  the ASN.1 primitive representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (request != null)
			{
				v.add(new DERTaggedObject(true, 0, request));
			}

			v.add(response);

			return new DERSequence(v);
		}
	}

}