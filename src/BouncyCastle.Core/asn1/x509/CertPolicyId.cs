namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// CertPolicyId, used in the CertificatePolicies and PolicyMappings
	/// X509V3 Extensions.
	/// 
	/// <pre>
	///     CertPolicyId ::= OBJECT IDENTIFIER
	/// </pre>
	/// </summary>
	/// <summary>
	/// CertPolicyId, used in the CertificatePolicies and PolicyMappings
	/// X509V3 Extensions.
	/// 
	/// <pre>
	///     CertPolicyId ::= OBJECT IDENTIFIER
	/// </pre>
	/// </summary>
	public class CertPolicyId : ASN1Object
	{
		private ASN1ObjectIdentifier id;

		private CertPolicyId(ASN1ObjectIdentifier id)
		{
			this.id = id;
		}

		public static CertPolicyId getInstance(object o)
		{
			if (o is CertPolicyId)
			{
				return (CertPolicyId)o;
			}
			else if (o != null)
			{
				return new CertPolicyId(ASN1ObjectIdentifier.getInstance(o));
			}

			return null;
		}

		public virtual string getId()
		{
			return id.getId();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return id;
		}
	}

}