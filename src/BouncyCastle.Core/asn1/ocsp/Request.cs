namespace org.bouncycastle.asn1.ocsp
{
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class Request : ASN1Object
	{
		internal CertID reqCert;
		internal Extensions singleRequestExtensions;

		public Request(CertID reqCert, Extensions singleRequestExtensions)
		{
			this.reqCert = reqCert;
			this.singleRequestExtensions = singleRequestExtensions;
		}

		private Request(ASN1Sequence seq)
		{
			reqCert = CertID.getInstance(seq.getObjectAt(0));

			if (seq.size() == 2)
			{
				singleRequestExtensions = Extensions.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true);
			}
		}

		public static Request getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static Request getInstance(object obj)
		{
			if (obj is Request)
			{
				return (Request)obj;
			}
			else if (obj != null)
			{
				return new Request(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual CertID getReqCert()
		{
			return reqCert;
		}

		public virtual Extensions getSingleRequestExtensions()
		{
			return singleRequestExtensions;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Request         ::=     SEQUENCE {
		///     reqCert                     CertID,
		///     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(reqCert);

			if (singleRequestExtensions != null)
			{
				v.add(new DERTaggedObject(true, 0, singleRequestExtensions));
			}

			return new DERSequence(v);
		}
	}

}