namespace org.bouncycastle.asn1.ocsp
{
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AuthorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess;

	public class ServiceLocator : ASN1Object
	{
		private readonly X500Name issuer;
		private readonly AuthorityInformationAccess locator;

		private ServiceLocator(ASN1Sequence sequence)
		{
			this.issuer = X500Name.getInstance(sequence.getObjectAt(0));
			if (sequence.size() == 2)
			{
				this.locator = AuthorityInformationAccess.getInstance(sequence.getObjectAt(1));
			}
			else
			{
				this.locator = null;

			}
		}

		public static ServiceLocator getInstance(object obj)
		{
			if (obj is ServiceLocator)
			{
				return (ServiceLocator)obj;
			}
			else if (obj != null)
			{
				return new ServiceLocator(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual X500Name getIssuer()
		{
			return issuer;
		}

		public virtual AuthorityInformationAccess getLocator()
		{
			return locator;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// ServiceLocator ::= SEQUENCE {
		///     issuer    Name,
		///     locator   AuthorityInfoAccessSyntax OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(issuer);

			if (locator != null)
			{
				v.add(locator);
			}

			return new DERSequence(v);
		}
	}

}