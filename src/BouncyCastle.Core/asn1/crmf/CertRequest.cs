namespace org.bouncycastle.asn1.crmf
{

	public class CertRequest : ASN1Object
	{
		private ASN1Integer certReqId;
		private CertTemplate certTemplate;
		private Controls controls;

		private CertRequest(ASN1Sequence seq)
		{
			certReqId = new ASN1Integer(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
			certTemplate = CertTemplate.getInstance(seq.getObjectAt(1));
			if (seq.size() > 2)
			{
				controls = Controls.getInstance(seq.getObjectAt(2));
			}
		}

		public static CertRequest getInstance(object o)
		{
			if (o is CertRequest)
			{
				return (CertRequest)o;
			}
			else if (o != null)
			{
				return new CertRequest(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertRequest(int certReqId, CertTemplate certTemplate, Controls controls) : this(new ASN1Integer(certReqId), certTemplate, controls)
		{
		}

		public CertRequest(ASN1Integer certReqId, CertTemplate certTemplate, Controls controls)
		{
			this.certReqId = certReqId;
			this.certTemplate = certTemplate;
			this.controls = controls;
		}

		public virtual ASN1Integer getCertReqId()
		{
			return certReqId;
		}

		public virtual CertTemplate getCertTemplate()
		{
			return certTemplate;
		}

		public virtual Controls getControls()
		{
			return controls;
		}

		/// <summary>
		/// <pre>
		/// CertRequest ::= SEQUENCE {
		///                      certReqId     INTEGER,          -- ID for matching request and reply
		///                      certTemplate  CertTemplate,  -- Selected fields of cert to be issued
		///                      controls      Controls OPTIONAL }   -- Attributes affecting issuance
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certReqId);
			v.add(certTemplate);

			if (controls != null)
			{
				v.add(controls);
			}

			return new DERSequence(v);
		}
	}

}