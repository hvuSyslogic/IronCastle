namespace org.bouncycastle.asn1.ocsp
{

	public class OCSPResponse : ASN1Object
	{
		internal OCSPResponseStatus responseStatus;
		internal ResponseBytes responseBytes;

		public OCSPResponse(OCSPResponseStatus responseStatus, ResponseBytes responseBytes)
		{
			this.responseStatus = responseStatus;
			this.responseBytes = responseBytes;
		}

		private OCSPResponse(ASN1Sequence seq)
		{
			responseStatus = OCSPResponseStatus.getInstance(seq.getObjectAt(0));

			if (seq.size() == 2)
			{
				responseBytes = ResponseBytes.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true);
			}
		}

		public static OCSPResponse getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static OCSPResponse getInstance(object obj)
		{
			if (obj is OCSPResponse)
			{
				return (OCSPResponse)obj;
			}
			else if (obj != null)
			{
				return new OCSPResponse(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual OCSPResponseStatus getResponseStatus()
		{
			return responseStatus;
		}

		public virtual ResponseBytes getResponseBytes()
		{
			return responseBytes;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// OCSPResponse ::= SEQUENCE {
		///     responseStatus         OCSPResponseStatus,
		///     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(responseStatus);

			if (responseBytes != null)
			{
				v.add(new DERTaggedObject(true, 0, responseBytes));
			}

			return new DERSequence(v);
		}
	}

}