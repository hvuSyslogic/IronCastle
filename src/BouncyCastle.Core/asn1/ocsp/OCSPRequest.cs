namespace org.bouncycastle.asn1.ocsp
{

	public class OCSPRequest : ASN1Object
	{
		internal TBSRequest tbsRequest;
		internal Signature optionalSignature;

		public OCSPRequest(TBSRequest tbsRequest, Signature optionalSignature)
		{
			this.tbsRequest = tbsRequest;
			this.optionalSignature = optionalSignature;
		}

		private OCSPRequest(ASN1Sequence seq)
		{
			tbsRequest = TBSRequest.getInstance(seq.getObjectAt(0));

			if (seq.size() == 2)
			{
				optionalSignature = Signature.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true);
			}
		}

		public static OCSPRequest getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static OCSPRequest getInstance(object obj)
		{
			if (obj is OCSPRequest)
			{
				return (OCSPRequest)obj;
			}
			else if (obj != null)
			{
				return new OCSPRequest(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual TBSRequest getTbsRequest()
		{
			return tbsRequest;
		}

		public virtual Signature getOptionalSignature()
		{
			return optionalSignature;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// OCSPRequest     ::=     SEQUENCE {
		///     tbsRequest                  TBSRequest,
		///     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsRequest);

			if (optionalSignature != null)
			{
				v.add(new DERTaggedObject(true, 0, optionalSignature));
			}

			return new DERSequence(v);
		}
	}

}