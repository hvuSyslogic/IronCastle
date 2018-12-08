using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.crmf
{


	public class CertReqMsg : ASN1Object
	{
		private CertRequest certReq;
		private ProofOfPossession pop;
		private ASN1Sequence regInfo;

		private CertReqMsg(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			certReq = CertRequest.getInstance(en.nextElement());
			while (en.hasMoreElements())
			{
				object o = en.nextElement();

				if (o is ASN1TaggedObject || o is ProofOfPossession)
				{
					pop = ProofOfPossession.getInstance(o);
				}
				else
				{
					regInfo = ASN1Sequence.getInstance(o);
				}
			}
		}

		public static CertReqMsg getInstance(object o)
		{
			if (o is CertReqMsg)
			{
				return (CertReqMsg)o;
			}
			else if (o != null)
			{
				return new CertReqMsg(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static CertReqMsg getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Creates a new CertReqMsg. </summary>
		/// <param name="certReq"> CertRequest </param>
		/// <param name="pop"> may be null </param>
		/// <param name="regInfo"> may be null </param>
		public CertReqMsg(CertRequest certReq, ProofOfPossession pop, AttributeTypeAndValue[] regInfo)
		{
			if (certReq == null)
			{
				throw new IllegalArgumentException("'certReq' cannot be null");
			}

			this.certReq = certReq;
			this.pop = pop;

			if (regInfo != null)
			{
				this.regInfo = new DERSequence(regInfo);
			}
		}

		public virtual CertRequest getCertReq()
		{
			return certReq;
		}


		/// @deprecated use getPopo 
		public virtual ProofOfPossession getPop()
		{
			return pop;
		}


		public virtual ProofOfPossession getPopo()
		{
			return pop;
		}

		public virtual AttributeTypeAndValue[] getRegInfo()
		{
			if (regInfo == null)
			{
				return null;
			}

			AttributeTypeAndValue[] results = new AttributeTypeAndValue[regInfo.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = AttributeTypeAndValue.getInstance(regInfo.getObjectAt(i));
			}

			return results;
		}

		/// <summary>
		/// <pre>
		/// CertReqMsg ::= SEQUENCE {
		///                    certReq   CertRequest,
		///                    popo       ProofOfPossession  OPTIONAL,
		///                    -- content depends upon key type
		///                    regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certReq);

			addOptional(v, pop);
			addOptional(v, regInfo);

			return new DERSequence(v);
		}

		private void addOptional(ASN1EncodableVector v, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(obj);
			}
		}
	}

}