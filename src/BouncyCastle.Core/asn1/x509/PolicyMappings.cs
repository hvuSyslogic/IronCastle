using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// PolicyMappings V3 extension, described in RFC3280.
	/// <pre>
	///    PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
	///      issuerDomainPolicy      CertPolicyId,
	///      subjectDomainPolicy     CertPolicyId }
	/// </pre>
	/// </summary>
	/// <seealso cref= <a href="http://www.faqs.org/rfc/rfc3280.txt">RFC 3280, section 4.2.1.6</a> </seealso>
	public class PolicyMappings : ASN1Object
	{
		internal ASN1Sequence seq = null;

		public static PolicyMappings getInstance(object obj)
		{
			if (obj is PolicyMappings)
			{
				return (PolicyMappings)obj;
			}
			if (obj != null)
			{
				return new PolicyMappings(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Creates a new <code>PolicyMappings</code> instance.
		/// </summary>
		/// <param name="seq"> an <code>ASN1Sequence</code> constructed as specified
		///            in RFC 3280 </param>
		private PolicyMappings(ASN1Sequence seq)
		{
			this.seq = seq;
		}

		/// <summary>
		/// Creates a new <code>PolicyMappings</code> instance.
		/// </summary>
		/// <param name="mappings"> a <code>HashMap</code> value that maps
		///                 <code>String</code> oids
		///                 to other <code>String</code> oids. </param>
		/// @deprecated use CertPolicyId constructors. 
		public PolicyMappings(Hashtable mappings)
		{
			ASN1EncodableVector dev = new ASN1EncodableVector();
			Enumeration it = mappings.keys();

			while (it.hasMoreElements())
			{
				string idp = (string)it.nextElement();
				string sdp = (string)mappings.get(idp);
				ASN1EncodableVector dv = new ASN1EncodableVector();
				dv.add(new ASN1ObjectIdentifier(idp));
				dv.add(new ASN1ObjectIdentifier(sdp));
				dev.add(new DERSequence(dv));
			}

			seq = new DERSequence(dev);
		}

		public PolicyMappings(CertPolicyId issuerDomainPolicy, CertPolicyId subjectDomainPolicy)
		{
			ASN1EncodableVector dv = new ASN1EncodableVector();
			dv.add(issuerDomainPolicy);
			dv.add(subjectDomainPolicy);

			seq = new DERSequence(new DERSequence(dv));
		}

		public PolicyMappings(CertPolicyId[] issuerDomainPolicy, CertPolicyId[] subjectDomainPolicy)
		{
			ASN1EncodableVector dev = new ASN1EncodableVector();

			for (int i = 0; i != issuerDomainPolicy.Length; i++)
			{
				ASN1EncodableVector dv = new ASN1EncodableVector();
				dv.add(issuerDomainPolicy[i]);
				dv.add(subjectDomainPolicy[i]);
				dev.add(new DERSequence(dv));
			}

			seq = new DERSequence(dev);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}