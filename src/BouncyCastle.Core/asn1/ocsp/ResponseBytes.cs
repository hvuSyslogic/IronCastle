namespace org.bouncycastle.asn1.ocsp
{

	public class ResponseBytes : ASN1Object
	{
		internal ASN1ObjectIdentifier responseType;
		internal ASN1OctetString response;

		public ResponseBytes(ASN1ObjectIdentifier responseType, ASN1OctetString response)
		{
			this.responseType = responseType;
			this.response = response;
		}

		/// @deprecated use getInstance() 
		public ResponseBytes(ASN1Sequence seq)
		{
			responseType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
			response = (ASN1OctetString)seq.getObjectAt(1);
		}

		public static ResponseBytes getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static ResponseBytes getInstance(object obj)
		{
			if (obj is ResponseBytes)
			{
				return (ResponseBytes)obj;
			}
			else if (obj != null)
			{
				return new ResponseBytes(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getResponseType()
		{
			return responseType;
		}

		public virtual ASN1OctetString getResponse()
		{
			return response;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// ResponseBytes ::=       SEQUENCE {
		///     responseType   OBJECT IDENTIFIER,
		///     response       OCTET STRING }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(responseType);
			v.add(response);

			return new DERSequence(v);
		}
	}

}