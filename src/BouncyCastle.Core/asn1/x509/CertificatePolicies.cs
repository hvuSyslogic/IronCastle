using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x509
{

	public class CertificatePolicies : ASN1Object
	{
		private readonly PolicyInformation[] policyInformation;

		public static CertificatePolicies getInstance(object obj)
		{
			if (obj is CertificatePolicies)
			{
				return (CertificatePolicies)obj;
			}

			if (obj != null)
			{
				return new CertificatePolicies(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static CertificatePolicies getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Retrieve a CertificatePolicies for a passed in Extensions object, if present.
		/// </summary>
		/// <param name="extensions"> the extensions object to be examined. </param>
		/// <returns>  the CertificatePolicies, null if the extension is not present. </returns>
		public static CertificatePolicies fromExtensions(Extensions extensions)
		{
			return CertificatePolicies.getInstance(extensions.getExtensionParsedValue(Extension.certificatePolicies));
		}

		/// <summary>
		/// Construct a CertificatePolicies object containing one PolicyInformation.
		/// </summary>
		/// <param name="name"> the name to be contained. </param>
		public CertificatePolicies(PolicyInformation name)
		{
			this.policyInformation = new PolicyInformation[] {name};
		}

		public CertificatePolicies(PolicyInformation[] policyInformation)
		{
			this.policyInformation = copyPolicyInfo(policyInformation);
		}

		private CertificatePolicies(ASN1Sequence seq)
		{
			this.policyInformation = new PolicyInformation[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				policyInformation[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
			}
		}

		public virtual PolicyInformation[] getPolicyInformation()
		{
			return copyPolicyInfo(policyInformation);
		}

		private PolicyInformation[] copyPolicyInfo(PolicyInformation[] policyInfo)
		{
			PolicyInformation[] tmp = new PolicyInformation[policyInfo.Length];

			JavaSystem.arraycopy(policyInfo, 0, tmp, 0, policyInfo.Length);

			return tmp;
		}

		public virtual PolicyInformation getPolicyInformation(ASN1ObjectIdentifier policyIdentifier)
		{
			for (int i = 0; i != policyInformation.Length; i++)
			{
				if (policyIdentifier.Equals(policyInformation[i].getPolicyIdentifier()))
				{
					 return policyInformation[i];
				}
			}

			return null;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(policyInformation);
		}

		public override string ToString()
		{
			StringBuffer p = new StringBuffer();
			for (int i = 0; i < policyInformation.Length; i++)
			{
				if (p.length() != 0)
				{
					p.append(", ");
				}
				p.append(policyInformation[i]);
			}

			return "CertificatePolicies: [" + p + "]";
		}
	}

}