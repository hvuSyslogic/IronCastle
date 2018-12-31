using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{
	
	public class POPOSigningKey : ASN1Object
	{
		private POPOSigningKeyInput poposkInput;
		private AlgorithmIdentifier algorithmIdentifier;
		private DERBitString signature;

		private POPOSigningKey(ASN1Sequence seq)
		{
			int index = 0;

			if (seq.getObjectAt(index) is ASN1TaggedObject)
			{
				ASN1TaggedObject tagObj = (ASN1TaggedObject)seq.getObjectAt(index++);
				if (tagObj.getTagNo() != 0)
				{
					throw new IllegalArgumentException("Unknown POPOSigningKeyInput tag: " + tagObj.getTagNo());
				}
				poposkInput = POPOSigningKeyInput.getInstance(tagObj.getObject());
			}
			algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
			signature = DERBitString.getInstance(seq.getObjectAt(index));
		}

		public static POPOSigningKey getInstance(object o)
		{
			if (o is POPOSigningKey)
			{
				return (POPOSigningKey)o;
			}

			if (o != null)
			{
				return new POPOSigningKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static POPOSigningKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Creates a new Proof of Possession object for a signing key.
		/// </summary>
		/// <param name="poposkIn">  the POPOSigningKeyInput structure, or null if the
		///                  CertTemplate includes both subject and publicKey values. </param>
		/// <param name="aid">       the AlgorithmIdentifier used to sign the proof of possession. </param>
		/// <param name="signature"> a signature over the DER-encoded value of poposkIn,
		///                  or the DER-encoded value of certReq if poposkIn is null. </param>
		public POPOSigningKey(POPOSigningKeyInput poposkIn, AlgorithmIdentifier aid, DERBitString signature)
		{
			this.poposkInput = poposkIn;
			this.algorithmIdentifier = aid;
			this.signature = signature;
		}

		public virtual POPOSigningKeyInput getPoposkInput()
		{
			return poposkInput;
		}

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return algorithmIdentifier;
		}

		public virtual DERBitString getSignature()
		{
			return signature;
		}

		/// <summary>
		/// <pre>
		/// POPOSigningKey ::= SEQUENCE {
		///                      poposkInput           [0] POPOSigningKeyInput OPTIONAL,
		///                      algorithmIdentifier   AlgorithmIdentifier,
		///                      signature             BIT STRING }
		///  -- The signature (using "algorithmIdentifier") is on the
		///  -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
		///  -- certReq CertTemplate contains the subject and publicKey values,
		///  -- then poposkInput MUST be omitted and the signature MUST be
		///  -- computed on the DER-encoded value of CertReqMsg certReq.  If
		///  -- the CertReqMsg certReq CertTemplate does not contain the public
		///  -- key and subject values, then poposkInput MUST be present and
		///  -- MUST be signed.  This strategy ensures that the public key is
		///  -- not present in both the poposkInput and CertReqMsg certReq
		///  -- CertTemplate fields.
		/// </pre>
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (poposkInput != null)
			{
				v.add(new DERTaggedObject(false, 0, poposkInput));
			}

			v.add(algorithmIdentifier);
			v.add(signature);

			return new DERSequence(v);
		}
	}

}