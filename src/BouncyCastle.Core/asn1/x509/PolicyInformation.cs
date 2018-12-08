using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class PolicyInformation : ASN1Object
	{
		private ASN1ObjectIdentifier policyIdentifier;
		private ASN1Sequence policyQualifiers;

		private PolicyInformation(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			policyIdentifier = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				policyQualifiers = ASN1Sequence.getInstance(seq.getObjectAt(1));
			}
		}

		public PolicyInformation(ASN1ObjectIdentifier policyIdentifier)
		{
			this.policyIdentifier = policyIdentifier;
		}

		public PolicyInformation(ASN1ObjectIdentifier policyIdentifier, ASN1Sequence policyQualifiers)
		{
			this.policyIdentifier = policyIdentifier;
			this.policyQualifiers = policyQualifiers;
		}

		public static PolicyInformation getInstance(object obj)
		{
			if (obj == null || obj is PolicyInformation)
			{
				return (PolicyInformation)obj;
			}

			return new PolicyInformation(ASN1Sequence.getInstance(obj));
		}

		public virtual ASN1ObjectIdentifier getPolicyIdentifier()
		{
			return policyIdentifier;
		}

		public virtual ASN1Sequence getPolicyQualifiers()
		{
			return policyQualifiers;
		}

		/*
		 * <pre>
		 * PolicyInformation ::= SEQUENCE {
		 *      policyIdentifier   CertPolicyId,
		 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
		 *              PolicyQualifierInfo OPTIONAL }
		 * </pre>
		 */ 
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(policyIdentifier);

			if (policyQualifiers != null)
			{
				v.add(policyQualifiers);
			}

			return new DERSequence(v);
		}

		public override string ToString()
		{
			StringBuffer sb = new StringBuffer();

			sb.append("Policy information: ");
			sb.append(policyIdentifier);

			if (policyQualifiers != null)
			{
				StringBuffer p = new StringBuffer();
				for (int i = 0; i < policyQualifiers.size(); i++)
				{
					if (p.length() != 0)
					{
						p.append(", ");
					}
					p.append(PolicyQualifierInfo.getInstance(policyQualifiers.getObjectAt(i)));
				}

				sb.append("[");
				sb.append(p);
				sb.append("]");
			}

			return sb.ToString();
		}
	}

}