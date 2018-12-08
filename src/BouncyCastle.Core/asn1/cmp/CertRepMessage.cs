using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{

	public class CertRepMessage : ASN1Object
	{
		private ASN1Sequence caPubs;
		private ASN1Sequence response;

		private CertRepMessage(ASN1Sequence seq)
		{
			int index = 0;

			if (seq.size() > 1)
			{
				caPubs = ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
			}

			response = ASN1Sequence.getInstance(seq.getObjectAt(index));
		}

		public static CertRepMessage getInstance(object o)
		{
			if (o is CertRepMessage)
			{
				return (CertRepMessage)o;
			}

			if (o != null)
			{
				return new CertRepMessage(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CertRepMessage(CMPCertificate[] caPubs, CertResponse[] response)
		{
			if (response == null)
			{
				throw new IllegalArgumentException("'response' cannot be null");
			}

			if (caPubs != null)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();
				for (int i = 0; i < caPubs.Length; i++)
				{
					v.add(caPubs[i]);
				}
				this.caPubs = new DERSequence(v);
			}

			{
				ASN1EncodableVector v = new ASN1EncodableVector();
				for (int i = 0; i < response.Length; i++)
				{
					v.add(response[i]);
				}
				this.response = new DERSequence(v);
			}
		}

		public virtual CMPCertificate[] getCaPubs()
		{
			if (caPubs == null)
			{
				return null;
			}

			CMPCertificate[] results = new CMPCertificate[caPubs.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = CMPCertificate.getInstance(caPubs.getObjectAt(i));
			}

			return results;
		}

		public virtual CertResponse[] getResponse()
		{
			CertResponse[] results = new CertResponse[response.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = CertResponse.getInstance(response.getObjectAt(i));
			}

			return results;
		}

		/// <summary>
		/// <pre>
		/// CertRepMessage ::= SEQUENCE {
		///                          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
		///                                                                             OPTIONAL,
		///                          response         SEQUENCE OF CertResponse
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (caPubs != null)
			{
				v.add(new DERTaggedObject(true, 1, caPubs));
			}

			v.add(response);

			return new DERSequence(v);
		}
	}

}